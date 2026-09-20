document.addEventListener('DOMContentLoaded',()=>{
 const header=document.querySelector('.site-header'); if(header){window.addEventListener('scroll',()=>header.classList.toggle('is-scrolled',window.scrollY>16));}
 const menuBtn=document.querySelector('.menu-toggle'), nav=document.querySelector('.site-nav'); if(menuBtn&&nav)menuBtn.addEventListener('click',()=>nav.classList.toggle('open'));
 const obs=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting)e.target.classList.add('in-view')}),{threshold:.08});document.querySelectorAll('.card,.step,.feature,.ai-band,.cta').forEach(x=>{x.classList.add('reveal');obs.observe(x)});
 document.querySelectorAll('.lead-form').forEach(form=>{form.addEventListener('submit',()=>{const b=form.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Sending…';}})});
});