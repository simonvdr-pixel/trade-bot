const CACHE = 'tradebot-v1';
const ASSETS = ['/', '/index.html'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).catch(() => caches.match('/index.html')))
  );
});

// ── Notificaties ───────────────────────────────────────────────────
// De app stuurt berichten naar de service worker zodra de bot iets
// belangrijks doet (koop, verkoop, fout). De service worker toont dan
// een systeemnotificatie — die werkt ook als de app op de achtergrond
// staat (scherm uit, andere app open), zolang de telefoon/browser de
// PWA niet volledig heeft afgesloten.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'TRADEBOT_NOTIFY') {
    const { title, body, tag, icon } = event.data;
    self.registration.showNotification(title, {
      body,
      tag,                 // zelfde tag = vervangt vorige melding i.p.v. opstapelen
      icon: icon || 'icons/icon-192.png',
      badge: 'icons/icon-192.png',
      vibrate: [100, 50, 100],
      timestamp: Date.now(),
    });
  }
});

// Klik op de notificatie opent (of focust) de app
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(clientsArr => {
      const existing = clientsArr.find(c => c.url.includes('index.html'));
      if (existing) return existing.focus();
      return self.clients.openWindow('index.html');
    })
  );
});
