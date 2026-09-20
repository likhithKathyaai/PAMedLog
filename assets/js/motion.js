(function(){
  'use strict';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) { document.documentElement.classList.add('pamed-reduced-motion'); return; }
  function init(){
    document.body.classList.add('pamed-motion-enabled');
    var selectors = ['.section > .container > h2','.section > .container > .eyebrow','.section > .container > p','.card','.service-card','.feature-card','.action-card','.case-card','.process-step','.step','.feature-panel','.form-card','.content-card','.article-card','.pricing-card','.footer-col','.page-hero .container > *'];
    var nodes=Array.prototype.slice.call(document.querySelectorAll(selectors.join(','))); var seen=new Set();
    nodes=nodes.filter(function(el){if(seen.has(el))return false;seen.add(el);return true;});
    nodes.forEach(function(el){el.classList.add('pamed-reveal');var parent=el.parentElement;if(parent){var siblings=Array.prototype.filter.call(parent.children,function(x){return nodes.indexOf(x)!==-1;});var idx=siblings.indexOf(el);el.style.setProperty('--pamed-delay',Math.min(idx*65,260)+'ms');}});
    if('IntersectionObserver'in window){var observer=new IntersectionObserver(function(entries){entries.forEach(function(entry){if(entry.isIntersecting){entry.target.classList.add('is-visible');observer.unobserve(entry.target);}});},{rootMargin:'0px 0px -8% 0px',threshold:0.08});nodes.forEach(function(el){observer.observe(el);});}else{nodes.forEach(function(el){el.classList.add('is-visible');});}
    var header=document.querySelector('.site-header');if(header){var onScroll=function(){header.classList.toggle('is-scrolled',window.scrollY>18);};onScroll();window.addEventListener('scroll',onScroll,{passive:true});}
    document.querySelectorAll('a[href^="#"]').forEach(function(a){a.addEventListener('click',function(e){var id=a.getAttribute('href');if(!id||id==='#')return;var target=document.querySelector(id);if(!target)return;e.preventDefault();target.scrollIntoView({behavior:'smooth',block:'start'});});});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();