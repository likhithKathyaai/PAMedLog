(()=>{
  'use strict';
  const root=document.querySelector('.kathya-assistant'); if(!root)return;
  const launch=root.querySelector('.kathya-launcher'),panel=root.querySelector('.kathya-panel'),close=root.querySelector('.kathya-close'),messages=root.querySelector('.kathya-messages'),form=root.querySelector('.kathya-compose'),input=root.querySelector('.kathya-input'),send=root.querySelector('.kathya-send');
  const cfg=window.pamedlogAssistant||{}; const history=[];
  const esc=s=>{const d=document.createElement('div');d.textContent=s;return d.innerHTML};
  function add(text,type){const el=document.createElement('div');el.className='kathya-message '+type;el.innerHTML=esc(text).replace(/\n/g,'<br>');messages.appendChild(el);messages.scrollTop=messages.scrollHeight;return el}
  function open(){panel.classList.add('is-open');panel.setAttribute('aria-hidden','false');launch.setAttribute('aria-expanded','true');setTimeout(()=>input.focus(),80)}
  function shut(){panel.classList.remove('is-open');panel.setAttribute('aria-hidden','true');launch.setAttribute('aria-expanded','false');launch.focus()}
  async function ask(q){
    if(!q.trim())return; add(q,'user'); input.value=''; send.disabled=true; input.disabled=true;
    const typing=add('Thinking…','bot'); typing.classList.add('is-typing');
    try{
      if(!cfg.endpoint) throw new Error('AI endpoint unavailable');
      const res=await fetch(cfg.endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-PA-MedLog-Nonce':cfg.nonce||''},body:JSON.stringify({message:q,history:history.slice(-8)})});
      const data=await res.json().catch(()=>({})); if(!res.ok) throw new Error((data&&data.message)||'KATHYA is temporarily unavailable.');
      const reply=(data.reply||'').trim(); if(!reply)throw new Error('No response received.');
      typing.remove(); add(reply,'bot'); history.push({role:'user',content:q},{role:'assistant',content:reply}); if(history.length>12)history.splice(0,history.length-12);
    }catch(e){typing.remove();add((e&&e.message?e.message:'KATHYA is temporarily unavailable.')+' You can also contact hr@pamedlogtalent.com.','bot')}
    finally{send.disabled=false;input.disabled=false;input.focus()}
  }
  launch.addEventListener('click',()=>panel.classList.contains('is-open')?shut():open()); close.addEventListener('click',shut); document.addEventListener('keydown',e=>{if(e.key==='Escape'&&panel.classList.contains('is-open'))shut()});
  form.addEventListener('submit',e=>{e.preventDefault();ask(input.value)});
  root.querySelectorAll('[data-kathya-link]').forEach(b=>b.addEventListener('click',()=>{const path=b.getAttribute('data-kathya-link');if(path)window.location.href=(cfg.homeUrl||'/').replace(/\/$/,'')+path;}));
  root.querySelectorAll('[data-kathya-prompt]').forEach(b=>b.addEventListener('click',()=>ask(b.getAttribute('data-kathya-prompt')||b.textContent)));
})();