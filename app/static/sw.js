const CACHE_NAME = 'booking-system-cache-v5';

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

// Push notification event
self.addEventListener('push', event => {
  const options = {
    body: event.data ? event.data.text() : 'Nova notificação',
    icon: '/static/icons/icon-192x192.png',
    badge: '/static/icons/icon-192x192.png',
    vibrate: [200, 100, 200],
    data: {
      url: '/dashboard?source=pwa'
    }
  };

  event.waitUntil(
    self.registration.showNotification('Poraqui - Agenda', options)
  );
});

// Notification click event
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data.url || '/dashboard?source=pwa')
  );
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