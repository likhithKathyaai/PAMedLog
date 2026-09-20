<?php
/* ===== V9 SECURITY BASELINE =====
 * Application-layer hardening only. Server/WAF/MFA/backups must be configured at hosting level.
 */
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);

function pamedlog_v9_security_headers(){
 if(headers_sent()) return;
 header('X-Content-Type-Options: nosniff');
 header('X-Frame-Options: SAMEORIGIN');
 header('Referrer-Policy: strict-origin-when-cross-origin');
 header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
 if(is_ssl()) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
add_action('send_headers','pamedlog_v9_security_headers');
add_filter('xmlrpc_enabled','__return_false');
remove_action('wp_head','wp_generator');
add_filter('the_generator','__return_empty_string');
function pamedlog_v9_hide_public_users($endpoints){
 if(!is_user_logged_in()){
  unset($endpoints['/wp/v2/users']);
  unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
 }
 return $endpoints;
}
add_filter('rest_endpoints','pamedlog_v9_hide_public_users');
function pamedlog_v9_login_errors(){return 'Login failed.';}
add_filter('login_errors','pamedlog_v9_login_errors');

if (!defined('ABSPATH')) exit;

function pamedlog_setup(){
  add_theme_support('title-tag'); add_theme_support('post-thumbnails'); add_theme_support('custom-logo'); add_theme_support('html5',['search-form','gallery','caption','style','script']);
  register_nav_menus(['primary'=>'Primary Menu','footer'=>'Footer Menu']);
}
add_action('after_setup_theme','pamedlog_setup');
function pamedlog_assets(){wp_enqueue_style('pamedlog-style',get_stylesheet_uri(),[],wp_get_theme()->get('Version'));}
add_action('wp_enqueue_scripts','pamedlog_assets');
function pamedlog_assistant_assets(){
 wp_enqueue_script('pamedlog-assistant',get_template_directory_uri().'/assets/js/assistant.js',[],wp_get_theme()->get('Version'),true);
 wp_localize_script('pamedlog-assistant','pamedlogAssistant',[
  'homeUrl'=>home_url('/'),
  'endpoint'=>rest_url('pamedlog/v1/assistant'),
  'nonce'=>wp_create_nonce('pamedlog_ai_chat'),
  'aiEnabled'=>pamedlog_ai_api_key() ? true : false
 ]);
}
add_action('wp_enqueue_scripts','pamedlog_assistant_assets');

function pamedlog_menu_fallback(){
 echo '<ul class="menu">';
 $items=['For Employers'=>'for-employers','For Candidates'=>'for-candidates','AI & Technology'=>'ai-solutions','Projects'=>'projects','Training'=>'training','Resources'=>'resources','Partners'=>'partners'];
 foreach($items as $label=>$slug) echo '<li><a href="'.esc_url(home_url('/'.$slug)).'">'.esc_html($label).'</a></li>';
 echo '</ul>';
}

/** V10.4: keep primary navigation focused. Home is available from the logo; About and Contact remain available contextually. */
function pamedlog_compact_primary_menu($items,$args){
 if(($args->theme_location ?? '')!=='primary') return $items;
 foreach($items as $k=>$item){
  $slug=trim((string)wp_parse_url($item->url,PHP_URL_PATH),'/');
  $label=strtolower(trim(wp_strip_all_tags($item->title)));
  if(in_array($slug,['','home','about','contact'],true) || in_array($label,['home','about','contact','pa medlog talent llc'],true)) unset($items[$k]);
 }
 return $items;
}
add_filter('wp_nav_menu_objects','pamedlog_compact_primary_menu',20,2);

function pamedlog_register_content(){
 register_post_type('pamed_lead',['labels'=>['name'=>'All Leads','singular_name'=>'Lead','menu_name'=>'Lead Center'],'public'=>false,'show_ui'=>true,'menu_icon'=>'dashicons-groups','supports'=>['title','editor','custom-fields']]);
 register_post_type('case_study',['labels'=>['name'=>'Case Studies','singular_name'=>'Case Study','add_new_item'=>'Add Case Study','edit_item'=>'Edit Case Study'],'public'=>true,'has_archive'=>false,'rewrite'=>['slug'=>'case-study'],'show_in_rest'=>true,'menu_icon'=>'dashicons-portfolio','supports'=>['title','editor','excerpt','thumbnail','custom-fields']]);
}
add_action('init','pamedlog_register_content');

function pamedlog_case_meta(){add_meta_box('pamed_case_details','Case Study Details','pamedlog_case_box','case_study','normal','high');}
add_action('add_meta_boxes','pamedlog_case_meta');
function pamedlog_case_box($post){wp_nonce_field('pamed_case_save','pamed_case_nonce'); $fields=['client'=>'Client / Project Name','industry'=>'Industry','challenge'=>'Challenge','solution'=>'Solution','outcomes'=>'Outcomes / Results']; foreach($fields as $k=>$l){$v=get_post_meta($post->ID,'case_'.$k,true); echo '<p><label><strong>'.esc_html($l).'</strong></label><br>'; if(in_array($k,['challenge','solution','outcomes'])) echo '<textarea style="width:100%;min-height:100px" name="case_'.$k.'">'.esc_textarea($v).'</textarea>'; else echo '<input style="width:100%" name="case_'.$k.'" value="'.esc_attr($v).'">'; echo '</p>';}}
function pamedlog_save_case($id){if(!current_user_can('edit_post',$id))return;if(!isset($_POST['pamed_case_nonce'])||!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['pamed_case_nonce'])),'pamed_case_save')||defined('DOING_AUTOSAVE')&&DOING_AUTOSAVE)return; foreach(['client','industry','challenge','solution','outcomes'] as $k) if(isset($_POST['case_'.$k])) update_post_meta($id,'case_'.$k,sanitize_textarea_field(wp_unslash($_POST['case_'.$k])));}
add_action('save_post_case_study','pamedlog_save_case');

function pamedlog_handle_form(){
 if(($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') wp_die('Invalid request.',403);
 if(!isset($_POST['pamed_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['pamed_nonce'])),'pamed_submit')) wp_die('Security check failed.',403);
 // Honeypot + minimum form-fill time reduce automated spam without tracking visitors.
 if(!empty($_POST['website'])) wp_die('Invalid submission.',400);
 $started=absint($_POST['form_started'] ?? 0);
 if(!$started || time()-$started < 2 || time()-$started > 7200) wp_die('Please reload the form and try again.',400);
 $ip=sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
 $rate_key='pamed_v9_'.hash('sha256',$ip.wp_salt('nonce'));
 $count=(int)get_transient($rate_key);
 if($count>=8) wp_die('Too many submissions. Please try again later.',429);
 set_transient($rate_key,$count+1,15*MINUTE_IN_SECONDS);

 $type=sanitize_text_field(wp_unslash($_POST['lead_type'] ?? 'General Inquiry')); $name=sanitize_text_field(wp_unslash($_POST['name'] ?? '')); $email=sanitize_email(wp_unslash($_POST['email'] ?? ''));
 if(mb_strlen($name)>120 || !$name || !$email || !is_email($email)){wp_safe_redirect(add_query_arg('form','error',wp_get_referer() ?: home_url('/contact/')));exit;}
 $keys=['phone'=>'Phone','company'=>'Company','role'=>'Role / Title','location'=>'Location','work_auth'=>'Work Authorization','experience'=>'Experience','service'=>'Service Needed','budget'=>'Budget','timeline'=>'Timeline','technology'=>'Technology / Skills','training'=>'Training Interest','job_type'=>'Hiring / Job Type','partnership'=>'Partnership Type','message'=>'Message / Requirement'];
 $data=['lead_type'=>$type,'name'=>$name,'email'=>$email,'source'=>esc_url_raw(wp_get_referer())]; $lines=["Lead Type: $type","Name: $name","Email: $email"];
 foreach($keys as $key=>$label){if(!empty($_POST[$key])){$val=sanitize_textarea_field(wp_unslash($_POST[$key]));if(mb_strlen($val)>5000)$val=mb_substr($val,0,5000);$data[$key]=$val;$lines[]="$label: $val";}}
 $id=wp_insert_post(['post_type'=>'pamed_lead','post_status'=>'publish','post_title'=>$type.' — '.$name.' — '.current_time('Y-m-d H:i'),'post_content'=>implode("\n",$lines)],true);
 if(is_wp_error($id)) wp_die('Unable to save your request. Please try again.',500);
 if(!empty($_FILES['resume']['name']) && !empty($_FILES['resume']['tmp_name'])){
  if((int)($_FILES['resume']['size'] ?? 0) > 5*MB_IN_BYTES) wp_die('Resume file is too large. Maximum size is 5 MB.',400);
  $allowed=['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
  $ft=wp_check_filetype_and_ext($_FILES['resume']['tmp_name'],$_FILES['resume']['name']);
  if(!in_array($ft['type'],$allowed,true)) wp_die('Unsupported resume format.',400);
  $path=pamedlog_private_resume_upload($_FILES['resume']); if($path){$data['resume_path']=$path;$lines[]='Resume uploaded: Yes (protected)';}
 }
 foreach($data as $k=>$v) update_post_meta($id,'lead_'.$k,$v);
 // Send every website enquiry to the PA MedLog inbox and acknowledge the sender.
 $recipient = apply_filters('pamedlog_enquiry_recipient','hr@pamedlogtalent.com');
 $admin_subject = sprintf('[PA MedLog Website] %s — %s',$type,$name);
 $admin_headers = ['Reply-To: '.$name.' <'.$email.'>'];
 $admin_sent = wp_mail($recipient,$admin_subject,implode("\n",$lines),$admin_headers);
 update_post_meta($id,'lead_email_notification',$admin_sent ? 'Sent' : 'Failed');
 update_post_meta($id,'lead_email_notification_time',current_time('mysql'));

 // Confirmation to the person who submitted the enquiry. No sensitive form details are echoed back.
 $ack_subject = 'We received your enquiry — PA MedLog Talent LLC';
 $ack_body = "Hello {$name},\n\nThank you for contacting PA MedLog Talent LLC. We received your {$type} enquiry and our team will review it.\n\nIf you need to add information, reply to this email or contact hr@pamedlogtalent.com.\n\nRegards,\nPA MedLog Talent LLC\nhttps://pamedlogtalent.com";
 $ack_headers = ['Reply-To: PA MedLog Talent LLC <hr@pamedlogtalent.com>'];
 $ack_sent = wp_mail($email,$ack_subject,$ack_body,$ack_headers);
 update_post_meta($id,'lead_acknowledgement',$ack_sent ? 'Sent' : 'Failed');

 wp_safe_redirect(add_query_arg('type',rawurlencode($type),home_url('/complete/')));exit;
}
add_action('admin_post_nopriv_pamed_submit','pamedlog_handle_form'); add_action('admin_post_pamed_submit','pamedlog_handle_form');

function pamedlog_lead_columns($cols){return ['cb'=>$cols['cb'],'title'=>'Lead','lead_type'=>'Type','lead_email'=>'Email','lead_company'=>'Company','lead_notice'=>'Email Notice','date'=>'Received'];}
add_filter('manage_pamed_lead_posts_columns','pamedlog_lead_columns');
function pamedlog_lead_column($col,$id){if($col==='lead_type')echo esc_html(get_post_meta($id,'lead_lead_type',true)); if($col==='lead_email')echo esc_html(get_post_meta($id,'lead_email',true)); if($col==='lead_company')echo esc_html(get_post_meta($id,'lead_company',true)); if($col==='lead_notice'){ $v=get_post_meta($id,'lead_email_notification',true); echo esc_html($v ?: 'Pending'); }}
add_action('manage_pamed_lead_posts_custom_column','pamedlog_lead_column',10,2);

function pamed_form($type,$fields,$button='Submit Information →'){
 if(isset($_GET['form'])&&$_GET['form']==='success') echo '<div class="notice">Thank you. Your information has been received and is now in our Lead Center.</div>';
 if(isset($_GET['form'])&&$_GET['form']==='error') echo '<div class="notice error">Please enter a valid name and email.</div>';
 echo '<form class="form-card lead-form" method="post" enctype="multipart/form-data" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="pamed_submit"><input type="hidden" name="lead_type" value="'.esc_attr($type).'"><input type="hidden" name="form_started" value="'.esc_attr(time()).'"><div class="hp-field" aria-hidden="true"><label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>'; wp_nonce_field('pamed_submit','pamed_nonce'); echo '<div class="form-grid">';
 foreach($fields as $f){$n=$f[0];$l=$f[1];$t=$f[2]??'text';$req=$f[3]??false;$full=($t==='textarea'); echo '<label class="'.($full?'full':'').'">'.esc_html($l).($req?' *':''); if($t==='textarea') echo '<textarea name="'.esc_attr($n).'" '.($req?'required':'').'></textarea>'; elseif($t==='file') echo '<input type="file" name="'.esc_attr($n).'" accept=".pdf,.doc,.docx" '.($req?'required':'').'>'; elseif(is_array($t)){echo '<select name="'.esc_attr($n).'" '.($req?'required':'').'><option value="">Select</option>';foreach($t as $o)echo '<option value="'.esc_attr($o).'">'.esc_html($o).'</option>';echo '</select>';} else echo '<input type="'.esc_attr($t).'" name="'.esc_attr($n).'" '.($req?'required':'').'>'; echo '</label>';}
 echo '</div><button class="btn btn-primary" type="submit">'.esc_html($button).'</button><p class="form-note">By submitting, you agree that PA MedLog Talent LLC may contact you about this request. Do not submit passwords, Social Security numbers, bank details or other sensitive information.</p></form>';
}
function pamed_basic_fields($extra=[]){return array_merge([['name','Full Name','text',true],['email','Email','email',true],['company','Company / Organization'],['location','Location']],$extra,[['message','Tell us what you need','textarea',true]]);}

function pamedlog_create_pages(){
 $pages=['Home','About','Services','Projects','AI Solutions','IT Projects','Staffing & Talent','Training','For Employers','For Candidates','Resources','Blog','Partners','Pricing','Contact','Complete','Privacy Policy','Generative AI Development','Machine Learning Engineering','Data Engineering','Software Development','Cloud & DevOps','Staff Augmentation','Corporate Training','Career Services','Industries','Engagement Models','Security & Data Handling','Terms of Use','Cookie Policy','Accessibility','Candidate Privacy Notice','KATHYA AI','AI Voice Agents','AI Automation','Cloud Services','Data & AI','IT Staffing','Healthcare Talent','Engineering Talent','AI Training'];
 foreach($pages as $title){if(!get_page_by_title($title,'OBJECT','page')) wp_insert_post(['post_title'=>$title,'post_content'=>'','post_status'=>'publish','post_type'=>'page']);}
 $home=get_page_by_title('Home'); if($home){update_option('show_on_front','page');update_option('page_on_front',$home->ID);} $blog=get_page_by_title('Blog'); if($blog) update_option('page_for_posts',$blog->ID);
}
add_action('after_switch_theme','pamedlog_create_pages');

function pamedlog_seed_blog(){
 if(get_option('pamedlog_seeded_v7')) return;
 $posts=[
  ['The Enterprise Guide to AI Agents','AI','AI agents are moving from experimentation into practical business workflows. This article explains where agents add value, how to choose a use case, what guardrails matter, and how to measure outcomes.'],
  ['How to Build a High-Performance Technology Team','Hiring','Strong technology teams combine clear role design, realistic hiring requirements, structured evaluation and an onboarding plan that connects talent to measurable business outcomes.'],
  ['AI and the Future of Workforce Productivity','Workforce','AI can augment teams by reducing repetitive work, improving access to information and accelerating routine decisions. Sustainable adoption requires governance, training and human accountability.'],
  ['A Practical Guide to Staff Augmentation','Hiring','Staff augmentation can help organizations add specialized capability for defined periods. This guide covers requirement design, engagement models, onboarding and performance expectations.'],
  ['Career Readiness for AI and Cloud Roles','Careers','Professionals targeting AI, data and cloud roles benefit from demonstrable projects, concise resumes, measurable outcomes and interview preparation grounded in real technical work.'],
  ['Corporate AI Training: From Awareness to Applied Skills','Training','Effective enterprise AI training should move beyond tool demonstrations. Teams need role-based learning, responsible-use guidance, practical exercises and measurable adoption goals.'],
  ['Planning an AI or Software Project: A Discovery Checklist','Technology','Before development begins, align users, workflows, integrations, data, security, ownership, timeline and success measures. Good discovery reduces expensive rework later.'],
  ['Responsible Hiring in a Global Technology Workforce','Hiring','Global hiring requires consistent evaluation, clear work authorization requirements, privacy-aware candidate handling and transparent communication throughout the process.']
 ];
 foreach($posts as $item){
  [$title,$category,$excerpt]=$item;
  $cat=term_exists($category,'category'); if(!$cat)$cat=wp_insert_term($category,'category');
  $cat_id=is_array($cat)?intval($cat['term_id']):intval($cat);
  if(!get_page_by_title($title,'OBJECT','post')) wp_insert_post(['post_title'=>$title,'post_content'=>'<p>'.esc_html($excerpt).'</p><h2>What to focus on</h2><p>Start with the business outcome, define a practical workflow, measure results and improve from real user feedback.</p>','post_excerpt'=>$excerpt,'post_status'=>'publish','post_type'=>'post','post_category'=>[$cat_id]]);
 }
 update_option('pamedlog_seeded_v7',1);
}
add_action('after_switch_theme','pamedlog_seed_blog');

function pamedlog_seo(){if(is_admin())return; global $post; $desc='PA MedLog Talent LLC provides AI solutions, IT project delivery, talent services and practical training for organizations and professionals.'; if(is_singular()&&has_excerpt($post))$desc=wp_strip_all_tags(get_the_excerpt($post)); echo '<meta name="description" content="'.esc_attr(wp_trim_words($desc,28,'')).'">' . "\n"; echo '<meta name="robots" content="index,follow,max-image-preview:large">' . "\n"; echo '<link rel="canonical" href="'.esc_url(is_singular()?get_permalink():home_url('/')).'">' . "\n"; echo '<meta property="og:site_name" content="PA MedLog Talent LLC"><meta property="og:type" content="'.(is_singular('post')?'article':'website').'"><meta property="og:title" content="'.esc_attr(wp_get_document_title()).'"><meta property="og:description" content="'.esc_attr(wp_trim_words($desc,28,'')).'"><meta property="og:url" content="'.esc_url(is_singular()?get_permalink():home_url('/')).'">' . "\n";
 $schema=['@context'=>'https://schema.org','@type'=>'Organization','name'=>'PA MedLog Talent LLC','url'=>home_url('/'),'email'=>'mailto:hr@pamedlogtalent.com','description'=>$desc]; echo '<script type="application/ld+json">'.wp_json_encode($schema).'</script>';
}
add_action('wp_head','pamedlog_seo',2);

/* ===== V4 PREMIUM UPGRADES ===== */
function pamedlog_v4_assets(){
 wp_enqueue_script('pamedlog-v4',get_template_directory_uri().'/assets/js/v4.js',[],wp_get_theme()->get('Version'),true);
}
add_action('wp_enqueue_scripts','pamedlog_v4_assets');

function pamedlog_motion_assets(){
 wp_enqueue_script('pamedlog-motion',get_template_directory_uri().'/assets/js/motion.js',[],wp_get_theme()->get('Version'),true);
}
add_action('wp_enqueue_scripts','pamedlog_motion_assets');

function pamedlog_v4_theme_support(){add_theme_support('align-wide'); add_theme_support('responsive-embeds');}
add_action('after_setup_theme','pamedlog_v4_theme_support');

function pamedlog_register_case_tax(){register_taxonomy('case_industry','case_study',['label'=>'Industries','public'=>true,'hierarchical'=>true,'show_in_rest'=>true]);}
add_action('init','pamedlog_register_case_tax');

function pamedlog_lead_status_box(){add_meta_box('pamed_lead_status','Lead Management','pamedlog_lead_status_render','pamed_lead','side','high');}
add_action('add_meta_boxes','pamedlog_lead_status_box');
function pamedlog_lead_status_render($post){wp_nonce_field('pamed_lead_status_save','pamed_lead_status_nonce');$s=get_post_meta($post->ID,'lead_status',true)?:'New';echo '<p><label><strong>Status</strong></label><select name="lead_status" style="width:100%">';foreach(['New','Contacted','Qualified','Proposal','Won','Lost'] as $x)echo '<option '.selected($s,$x,false).'>'.esc_html($x).'</option>';echo '</select></p><p><label><strong>Internal Notes</strong></label><textarea name="lead_notes" style="width:100%;min-height:100px">'.esc_textarea(get_post_meta($post->ID,'lead_notes',true)).'</textarea></p>';}
function pamedlog_lead_status_save($id){if(!isset($_POST['pamed_lead_status_nonce'])||!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['pamed_lead_status_nonce'])),'pamed_lead_status_save'))return;if(isset($_POST['lead_status']))update_post_meta($id,'lead_status',sanitize_text_field(wp_unslash($_POST['lead_status'])));if(isset($_POST['lead_notes']))update_post_meta($id,'lead_notes',sanitize_textarea_field(wp_unslash($_POST['lead_notes'])));}
add_action('save_post_pamed_lead','pamedlog_lead_status_save');

function pamedlog_v4_lead_columns($cols){$cols['lead_status']='Status';return $cols;}
add_filter('manage_pamed_lead_posts_columns','pamedlog_v4_lead_columns',20);
function pamedlog_v4_lead_column($col,$id){if($col==='lead_status')echo '<strong>'.esc_html(get_post_meta($id,'lead_status',true)?:'New').'</strong>';}
add_action('manage_pamed_lead_posts_custom_column','pamedlog_v4_lead_column',20,2);

function pamedlog_dashboard_menu(){add_submenu_page('edit.php?post_type=pamed_lead','Lead Dashboard','Dashboard','edit_posts','pamed-lead-dashboard','pamedlog_dashboard_page');}
add_action('admin_menu','pamedlog_dashboard_menu');
function pamedlog_dashboard_page(){if(!current_user_can('edit_posts'))return;$total=wp_count_posts('pamed_lead')->publish;$statuses=['New','Contacted','Qualified','Proposal','Won','Lost'];echo '<div class="wrap"><h1>PA MedLog Lead Dashboard</h1><p>One place for website enquiries and conversion follow-up.</p><div style="display:flex;gap:12px;flex-wrap:wrap">';echo '<div class="card"><h2>'.intval($total).'</h2><p>Total Leads</p></div>';foreach($statuses as $s){$q=new WP_Query(['post_type'=>'pamed_lead','post_status'=>'publish','meta_key'=>'lead_status','meta_value'=>$s,'posts_per_page'=>1]);echo '<div class="card"><h2>'.intval($q->found_posts).'</h2><p>'.esc_html($s).'</p></div>';}echo '</div><p><a class="button button-primary" href="'.esc_url(admin_url('edit.php?post_type=pamed_lead')).'">Open All Leads</a></p></div>';}

function pamedlog_seed_v4_pages(){
 foreach(['KATHYA AI','AI Voice Agents','AI Automation','Cloud Services','Data & AI','IT Staffing','Healthcare Talent','Engineering Talent','AI Training'] as $title){if(!get_page_by_title($title,'OBJECT','page'))wp_insert_post(['post_title'=>$title,'post_status'=>'publish','post_type'=>'page']);}
}
add_action('after_switch_theme','pamedlog_seed_v4_pages');

function pamedlog_breadcrumbs(){return;} // V10.4: removed visible breadcrumb trail; logo is the Home control.


// Lightweight inline SVG icon set — no external icon library or font required.
function pamed_icon($name='sparkles'){
    $icons=[
      'sparkles'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.2 3.8L17 8l-3.8 1.2L12 13l-1.2-3.8L7 8l3.8-1.2L12 3Zm6 9 .8 2.2L21 15l-2.2.8L18 18l-.8-2.2L15 15l2.2-.8L18 12ZM6 13l1 3 3 1-3 1-1 3-1-3-3-1 3-1 1-3Z"/></svg>',
      'code'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8.5 6-6 6 6 6M15.5 6l6 6-6 6M14 3l-4 18"/></svg>',
      'users'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
      'graduation'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m2 10 10-5 10 5-10 5L2 10Zm4 2.5V17c3 2.2 9 2.2 12 0v-4.5M22 10v6"/></svg>',
      'briefcase'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2M3 7h18v13H3V7Zm0 5c5 3 13 3 18 0M10 13h4"/></svg>',
      'handshake'=>'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8 12 3 3c1 1 2.5 1 3.5 0l4.5-4.5M2 9l4-4 4 4-4 4-4-4Zm20 0-4-4-3 3M7 13l4 4c1 1 2 1 3 0M9 15l-1 1c-.8.8-2.2.8-3 0l-1-1"/></svg>',
    ];
    echo $icons[$name] ?? $icons['sparkles'];
}

/* ===== V8 ENTERPRISE / PRODUCTION UPGRADES ===== */
function pamedlog_v8_pages(){
 $pages=['Industries','Engagement Models','Security & Data Handling','Terms of Use','Cookie Policy','Accessibility','Candidate Privacy Notice','AI Agents','Voice AI','Workflow Automation','Healthcare','Financial Services','Retail & eCommerce','Manufacturing','Professional Services'];
 foreach($pages as $title){if(!get_page_by_title($title,'OBJECT','page'))wp_insert_post(['post_title'=>$title,'post_status'=>'publish','post_type'=>'page']);}
}
add_action('after_switch_theme','pamedlog_v8_pages');

// CSV export for authorized administrators.
function pamedlog_export_leads(){
 if(!current_user_can('manage_options'))wp_die('Not allowed.',403); check_admin_referer('pamed_export_leads');
 $q=new WP_Query(['post_type'=>'pamed_lead','post_status'=>'publish','posts_per_page'=>-1,'orderby'=>'date','order'=>'DESC']);
 nocache_headers(); header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename=pamedlog-leads-'.gmdate('Y-m-d').'.csv');
 $out=fopen('php://output','w'); fputcsv($out,['Date','Lead Type','Name','Email','Company','Location','Service','Budget','Timeline','Status','Source','Message']);
 foreach($q->posts as $p){$g=function($k)use($p){return get_post_meta($p->ID,'lead_'.$k,true);};fputcsv($out,[get_the_date('c',$p),$g('lead_type'),$g('name'),$g('email'),$g('company'),$g('location'),$g('service'),$g('budget'),$g('timeline'),get_post_meta($p->ID,'lead_status',true)?:'New',$g('source'),$g('message')]);}
 fclose($out); exit;
}
add_action('admin_post_pamed_export_leads','pamedlog_export_leads');
function pamedlog_export_button(){global $typenow;if($typenow==='pamed_lead'&&current_user_can('manage_options')){ $u=wp_nonce_url(admin_url('admin-post.php?action=pamed_export_leads'),'pamed_export_leads'); echo '<script>document.addEventListener("DOMContentLoaded",function(){var h=document.querySelector(".wrap .wp-heading-inline");if(h){var a=document.createElement("a");a.className="page-title-action";a.href='.wp_json_encode($u).';a.textContent="Export CSV";h.after(a);}});</script>';}}
add_action('admin_footer-edit.php','pamedlog_export_button');

// Simple admin-only protected resume download. New uploads use a non-public folder when possible.
function pamedlog_private_resume_upload($file){
 $dir=trailingslashit(WP_CONTENT_DIR).'pamedlog-private';if(!wp_mkdir_p($dir))return false;
 if(!file_exists($dir.'/.htaccess'))@file_put_contents($dir.'/.htaccess',"Require all denied\nDeny from all\n");
 if(!file_exists($dir.'/index.php'))@file_put_contents($dir.'/index.php',"<?php http_response_code(403); exit;\n");
 if(!file_exists($dir.'/web.config'))@file_put_contents($dir.'/web.config','<configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>');
 $ext=strtolower(pathinfo(sanitize_file_name($file['name']),PATHINFO_EXTENSION));$name=wp_generate_password(32,false,false).'.'.$ext;$dest=trailingslashit($dir).$name;
 return move_uploaded_file($file['tmp_name'],$dest)?$dest:false;
}
function pamedlog_resume_download(){if(!current_user_can('manage_options'))wp_die('Not allowed.');$id=absint($_GET['lead']??0);check_admin_referer('pamed_resume_'.$id);$path=get_post_meta($id,'lead_resume_path',true);if(!$path||!is_file($path))wp_die('File unavailable.');$type=wp_check_filetype($path);header('Content-Type: '.($type['type']?:'application/octet-stream'));header('Content-Disposition: attachment; filename="'.basename($path).'"');header('Content-Length: '.filesize($path));readfile($path);exit;}
add_action('admin_post_pamed_resume_download','pamedlog_resume_download');
function pamedlog_resume_box(){add_meta_box('pamed_resume','Candidate Document','pamedlog_resume_box_render','pamed_lead','side');}
add_action('add_meta_boxes','pamedlog_resume_box');
function pamedlog_resume_box_render($post){$p=get_post_meta($post->ID,'lead_resume_path',true);if($p){$u=wp_nonce_url(admin_url('admin-post.php?action=pamed_resume_download&lead='.$post->ID),'pamed_resume_'.$post->ID);echo '<p>Protected candidate document.</p><a class="button" href="'.esc_url($u).'">Download Resume</a>';}else echo '<p>No protected resume attached.</p>';}

// Replace legacy public resume URL with protected path for new candidate submissions.
function pamedlog_v8_capture_resume($id){if(get_post_type($id)!=='pamed_lead'||empty($_FILES['resume']['name'])||empty($_FILES['resume']['tmp_name']))return;$ft=wp_check_filetype_and_ext($_FILES['resume']['tmp_name'],$_FILES['resume']['name']);$allowed=['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document'];if(in_array($ft['type'],$allowed,true)){ $copy=['name'=>$_FILES['resume']['name'],'tmp_name'=>$_FILES['resume']['tmp_name']];$path=pamedlog_private_resume_upload($copy);if($path)update_post_meta($id,'lead_resume_path',$path);}}
// Note: main handler stores the lead before redirect. Private storage is integrated below through upload filtering.

function pamedlog_faq_schema(){if(!is_page())return;$slug=get_post_field('post_name',get_queried_object_id());$faq=[];if($slug==='engagement-models')$faq=[['How are engagements scoped?','Scope, timeline, responsibilities and commercial terms are agreed in writing before delivery.'],['Can services be combined?','Yes. Projects, talent and training can be structured together when appropriate.']];if($slug==='security-data-handling')$faq=[['Do website forms request sensitive data?','No. Visitors are instructed not to submit passwords, Social Security numbers or banking credentials.'],['Who can access candidate documents?','Candidate documents should be limited to authorized administrators and handled according to the organization’s retention and privacy practices.']];if(!$faq)return;$d=['@context'=>'https://schema.org','@type'=>'FAQPage','mainEntity'=>[]];foreach($faq as $x)$d['mainEntity'][]=['@type'=>'Question','name'=>$x[0],'acceptedAnswer'=>['@type'=>'Answer','text'=>$x[1]]];echo '<script type="application/ld+json">'.wp_json_encode($d).'</script>';}
add_action('wp_head','pamedlog_faq_schema',20);

/* Shared front-end rendering helpers */
function pamed_page_intro($title,$subtitle,$copy,$features){
 $icon_names=['sparkles','code','users','graduation','briefcase','handshake'];
 echo '<section class="page-hero premium-page-hero"><div class="wrap page-hero-grid"><div><span class="eyebrow">PA MedLog Talent LLC</span><h1>'.esc_html($title).'</h1><p>'.esc_html($subtitle).'</p></div><div class="page-hero-note"><span>Outcome focused</span><strong>Clear scope. Practical execution.</strong><p>'.esc_html($copy).'</p></div></div></section>';
 echo '<section class="section premium-capabilities"><div class="wrap"><div class="section-head clean-head"><div><span class="eyebrow">Capabilities</span><h2>Built around what you need next.</h2></div><p>Explore focused capabilities designed to move from requirement to action without unnecessary complexity.</p></div><div class="capability-grid">';
 foreach($features as $i=>$x){$n=str_pad((string)($i+1),2,'0',STR_PAD_LEFT);echo '<article class="capability-card"><div class="capability-top"><span class="icon">';pamed_icon($icon_names[$i%count($icon_names)]);echo '</span><span class="cap-number">'.$n.'</span></div><h3>'.esc_html($x).'</h3><p>Flexible support shaped around your goals, timeline and operating requirements.</p></article>';}
 echo '</div><div class="simple-cta premium-inline-cta"><div><span class="eyebrow">Next step</span><h3>Have a requirement in mind?</h3><p>Share the outcome you need. We’ll route it to the right workflow and next step.</p></div><a class="btn btn-primary" href="'.esc_url(home_url('/contact')).'">Start a Conversation →</a></div></div></section>';
}
function pamed_case_highlights($context='general'){
 $q=new WP_Query(['post_type'=>'case_study','post_status'=>'publish','posts_per_page'=>3]);
 echo '<section class="section case-highlight-section"><div class="wrap"><div class="section-head"><div><span class="eyebrow">Case Studies</span><h2>From challenge to measurable outcome.</h2></div><p>Published case studies appear only after client/project information has been reviewed and approved for publication.</p></div>';
 if($q->have_posts()){echo '<div class="case-highlight-grid">';while($q->have_posts()){$q->the_post();$industry=get_post_meta(get_the_ID(),'case_industry',true);$challenge=get_post_meta(get_the_ID(),'case_challenge',true);$outcome=get_post_meta(get_the_ID(),'case_outcomes',true);echo '<article class="case-highlight-card"><span class="mini-label">'.esc_html($industry?:'Case Study').'</span><h3>'.esc_html(get_the_title()).'</h3><p><strong>Challenge</strong><br>'.esc_html(wp_trim_words($challenge,18)).'</p><p><strong>Outcome</strong><br>'.esc_html(wp_trim_words($outcome,18)).'</p><a class="link" href="'.esc_url(get_permalink()).'">View case study →</a></article>';}echo '</div>';wp_reset_postdata();}
 else {echo '<div class="case-placeholder-grid"><article><span class="mini-label">AI & Automation</span><h3>Conversational AI workflow</h3><p>Case studies in this area will show the business challenge, workflow design, integrations, guardrails and verified results.</p></article><article><span class="mini-label">Talent</span><h3>Specialist team delivery</h3><p>Talent case studies will document role requirements, delivery approach, onboarding model and approved hiring outcomes.</p></article><article><span class="mini-label">Training</span><h3>Workforce upskilling</h3><p>Training case studies will cover learning goals, program structure, participation and verified capability outcomes.</p></article></div><p class="proof-note">These are case-study categories, not claims about completed client engagements. Add verified stories in WordPress Admin → Case Studies.</p>';}
 echo '<div class="section-action"><a class="btn btn-outline" href="'.esc_url(home_url('/projects')).'">Explore Projects & Case Studies →</a></div></div></section>';
}

/* ===== V8.3 CONTENT EXPANSION ===== */
function pamedlog_seed_v83_content(){
 if(get_option('pamedlog_seeded_v83')) return;
 $posts=[
  ['Top IT Skills U.S. Companies Are Hiring For','Hiring','A practical framework for evaluating demand across AI, cloud, data, DevOps, cybersecurity and software engineering.'],
  ['AWS vs Azure: Which Cloud Platform Should You Learn?','Careers','Compare cloud learning paths based on target roles, existing experience and the environments used by prospective employers.'],
  ['How to Start a Career in AI & GenAI','Careers','A project-first roadmap for building foundations in Python, data, LLM concepts, evaluation and practical AI applications.'],
  ['What Does a Data Engineer Do?','Careers','Understand pipelines, ETL and ELT, data platforms, orchestration, quality and the skills expected in modern data engineering.'],
  ['How IT Staffing Works','Hiring','An employer-focused overview of requirements, sourcing, screening, engagement models, interviews and onboarding.'],
  ['How to Prepare for a U.S. IT Interview','Careers','Prepare for recruiter, technical and behavioral rounds with concise examples, project evidence and role-specific practice.'],
  ['Top DevOps Skills to Learn','Careers','A practical learning sequence covering Linux, Git, CI/CD, containers, Kubernetes, cloud, infrastructure automation and observability.'],
  ['AI Engineer vs Data Engineer','Careers','Compare responsibilities, core skills, project types and career paths across AI engineering and data engineering.'],
  ['How to Build an ATS-Friendly Resume','Careers','Use clear structure, role-relevant keywords, measurable outcomes and concise project evidence without keyword stuffing.'],
  ['How Companies Hire IT Contractors','Hiring','A practical view of requirement definition, supplier engagement, screening, interviews, onboarding and performance expectations.'],
  ['Contract vs Direct Hire IT Staffing','Hiring','Compare flexibility, duration, ownership, onboarding and workforce planning considerations for common hiring models.'],
  ['How to Choose an IT Staffing Partner','Hiring','Evaluate specialization, process quality, communication, candidate handling, compliance practices and delivery transparency.']
 ];
 foreach($posts as $item){[$title,$category,$excerpt]=$item;$cat=term_exists($category,'category');if(!$cat)$cat=wp_insert_term($category,'category');$cat_id=is_array($cat)?intval($cat['term_id']):intval($cat);if(!get_page_by_title($title,'OBJECT','post'))wp_insert_post(['post_title'=>$title,'post_content'=>'<p>'.esc_html($excerpt).'</p><h2>Key considerations</h2><p>Use this article as a practical starting point. Adapt decisions to the role, organization, market and applicable requirements.</p>','post_excerpt'=>$excerpt,'post_status'=>'publish','post_type'=>'post','post_category'=>[$cat_id]]);}
 // Draft-only case study templates: visible to admins, never presented as completed client work until verified and published.
 $drafts=[
  ['AI Voice & Workflow Automation — Case Study Template','AI & Automation'],
  ['Specialist Technology Team — Case Study Template','Talent'],
  ['Corporate Upskilling Program — Case Study Template','Training']
 ];
 foreach($drafts as $d){if(!get_page_by_title($d[0],'OBJECT','case_study')){$id=wp_insert_post(['post_title'=>$d[0],'post_content'=>'Replace this template with verified, client-approved details before publishing.','post_status'=>'draft','post_type'=>'case_study']);if($id){update_post_meta($id,'case_industry',$d[1]);update_post_meta($id,'case_challenge','Describe the verified business challenge.');update_post_meta($id,'case_solution','Describe the verified PA MedLog approach and delivery.');update_post_meta($id,'case_outcomes','Add only verified, approved outcomes or measurable results.');}}}
 update_option('pamedlog_seeded_v83',1);
}
add_action('after_switch_theme','pamedlog_seed_v83_content');


/* ===== V10.3 LIVE GENERATIVE AI BACKEND ===== */
function pamedlog_ai_api_key(){
    if(defined('PAMEDLOG_OPENAI_API_KEY') && PAMEDLOG_OPENAI_API_KEY){ return trim((string)PAMEDLOG_OPENAI_API_KEY); }
    $env=getenv('OPENAI_API_KEY');
    return $env ? trim((string)$env) : '';
}
function pamedlog_ai_model(){
    return defined('PAMEDLOG_OPENAI_MODEL') && PAMEDLOG_OPENAI_MODEL ? sanitize_text_field(PAMEDLOG_OPENAI_MODEL) : 'gpt-5.6-luna';
}
function pamedlog_ai_client_id(){
    $ip=isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
    return hash_hmac('sha256',$ip,wp_salt('auth'));
}
function pamedlog_ai_rate_limited(){
    $key='pamedlog_ai_'.substr(pamedlog_ai_client_id(),0,32);
    $hits=(int)get_transient($key);
    if($hits>=20){ return true; }
    set_transient($key,$hits+1,MINUTE_IN_SECONDS);
    return false;
}
function pamedlog_ai_instructions(){
    return "You are KATHYA Assistant, the website AI assistant for PA MedLog Talent LLC. Help visitors understand PA MedLog services and choose the right next step. Services include IT staffing and talent solutions, AI and workflow automation, KATHYA conversational/voice AI, software/cloud/data/DevOps projects, corporate technology training, candidate career support, and business partnerships. Public contact email: hr@pamedlogtalent.com. Never invent client names, case-study results, job openings, prices, guarantees, legal claims, visa advice, or employment outcomes. Do not claim a human has reviewed anything. For account-specific, hiring-specific, candidate-specific, payment, legal, immigration, or confidential matters, recommend contacting the team. Keep answers concise, useful, professional, and usually under 120 words. Do not ask users to share passwords, government IDs, financial account details, medical data, or other highly sensitive information in chat. When relevant, point users to these website paths: /for-employers, /for-candidates, /projects, /ai-solutions, /kathya-ai, /training, /partners, /contact. If uncertain, say so rather than making up information.";
}
function pamedlog_ai_extract_text($data){
    if(!empty($data['output_text']) && is_string($data['output_text'])) return trim($data['output_text']);
    if(!empty($data['output']) && is_array($data['output'])){
        $parts=[];
        foreach($data['output'] as $item){
            if(($item['type']??'')!=='message' || empty($item['content']) || !is_array($item['content'])) continue;
            foreach($item['content'] as $content){
                if(($content['type']??'')==='output_text' && !empty($content['text'])) $parts[]=$content['text'];
            }
        }
        return trim(implode("\n",$parts));
    }
    return '';
}
function pamedlog_ai_rest_chat(WP_REST_Request $request){
    $nonce=$request->get_header('X-PA-MedLog-Nonce');
    if(!$nonce || !wp_verify_nonce($nonce,'pamedlog_ai_chat')) return new WP_Error('invalid_request','Please refresh the page and try again.',['status'=>403]);
    if(pamedlog_ai_rate_limited()) return new WP_Error('rate_limit','Too many messages. Please wait a minute and try again.',['status'=>429]);
    $key=pamedlog_ai_api_key();
    if(!$key) return new WP_Error('ai_not_configured','Live AI is not configured yet. Please contact hr@pamedlogtalent.com.',['status'=>503]);
    $params=$request->get_json_params();
    $message=isset($params['message']) ? trim(sanitize_textarea_field($params['message'])) : '';
    if($message==='' || mb_strlen($message)>1200) return new WP_Error('invalid_message','Please enter a message under 1,200 characters.',['status'=>400]);
    $history=[];
    if(!empty($params['history']) && is_array($params['history'])){
        foreach(array_slice($params['history'],-8) as $row){
            $role=($row['role']??'')==='assistant' ? 'assistant' : 'user';
            $text=isset($row['content']) ? trim(sanitize_textarea_field($row['content'])) : '';
            if($text!=='') $history[]=['role'=>$role,'content'=>mb_substr($text,0,1200)];
        }
    }
    $history[]=['role'=>'user','content'=>$message];
    $payload=[
        'model'=>pamedlog_ai_model(),
        'instructions'=>pamedlog_ai_instructions(),
        'input'=>$history,
        'max_output_tokens'=>260,
        'store'=>false,
        'text'=>['verbosity'=>'low']
    ];
    $response=wp_remote_post('https://api.openai.com/v1/responses',[
        'timeout'=>30,
        'redirection'=>0,
        'headers'=>['Authorization'=>'Bearer '.$key,'Content-Type'=>'application/json'],
        'body'=>wp_json_encode($payload),
        'data_format'=>'body'
    ]);
    if(is_wp_error($response)) return new WP_Error('ai_unavailable','The AI service is temporarily unavailable. Please try again shortly.',['status'=>502]);
    $status=(int)wp_remote_retrieve_response_code($response);
    $data=json_decode(wp_remote_retrieve_body($response),true);
    if($status<200 || $status>=300){
        if(defined('WP_DEBUG') && WP_DEBUG) error_log('PA MedLog AI API error HTTP '.$status);
        return new WP_Error('ai_error','KATHYA could not respond right now. Please try again or contact hr@pamedlogtalent.com.',['status'=>502]);
    }
    $text=pamedlog_ai_extract_text(is_array($data)?$data:[]);
    if($text==='') return new WP_Error('empty_ai_response','KATHYA did not return a response. Please try again.',['status'=>502]);
    return rest_ensure_response(['reply'=>$text]);
}
function pamedlog_register_ai_route(){
    register_rest_route('pamedlog/v1','/assistant',[
        'methods'=>'POST',
        'callback'=>'pamedlog_ai_rest_chat',
        'permission_callback'=>'__return_true'
    ]);
}
add_action('rest_api_init','pamedlog_register_ai_route');
