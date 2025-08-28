const CACHE = 'sus-cache-v1';
const ASSETS = [
  '/',
  '/static/css/style.css',
  '/static/js/script.js',
  // 如有 logo / 字体等可继续添加
];
self.addEventListener('install', (e)=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=> self.skipWaiting()));
});
self.addEventListener('activate', (e)=>{ e.waitUntil(self.clients.claim()); });

// 资源：缓存优先；API：网络优先
self.addEventListener('fetch', (e)=>{
  const url = new URL(e.request.url);
  const isAPI = /\/api|\/login|\/user\//.test(url.pathname);
  if (isAPI){
    e.respondWith(
      fetch(e.request).catch(()=> caches.match(e.request))
    );
  } else {
    e.respondWith(
      caches.match(e.request).then(res=> res || fetch(e.request).then(net=>{
        const copy = net.clone(); caches.open(CACHE).then(c=> c.put(e.request, copy)); return net;
      }))
    );
  }
});