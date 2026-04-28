const CACHE_NAME = 'booking-system-cache-v4';

const STATIC_ASSETS = [
  '/static/css/styles.css',
  '/static/js/scripts.js'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(key => {
        if (key !== CACHE_NAME) return caches.delete(key);
      }))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // 🔥 NÃO cachear HTML nem API
  if (url.pathname.startsWith('/api') || url.pathname === '/' || url.pathname.startsWith('/dashboard')) {
    return;
  }

  // ✅ cache só arquivos estáticos
  if (url.pathname.startsWith('/static')) {
    event.respondWith(
      caches.match(event.request).then(response => {
        return response || fetch(event.request);
      })
    );
  }
});