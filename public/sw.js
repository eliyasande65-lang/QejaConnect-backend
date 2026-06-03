// QejaConnect Service Worker v3
const CACHE_NAME = 'qejaconnect-v3';

const CORE_ASSETS = [
  '/QejaConnect/welcome.html',
  '/QejaConnect/offline.html',
  '/QejaConnect/logo.jpg',
  '/QejaConnect/manifest.json'
];

// Install
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

// Activate
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
  // Start notification timer when SW activates
  scheduleNotification();
});

// Fetch
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request)
      .then(response => {
        if (response.ok && event.request.url.includes('/QejaConnect/')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => {
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          if (event.request.headers.get('Accept').includes('text/html')) {
            return caches.match('/QejaConnect/offline.html');
          }
        });
      })
  );
});

// Notification messages — rotated so it doesn't feel repetitive
const MESSAGES = [
  {
    title: '🏠 New Properties on QejaConnect',
    body: 'Come and see the new properties before spaces are filled up!'
  },
  {
    title: '🔑 Fresh Listings Just Added',
    body: 'Landlords just posted new spaces. Check them out before they\'re gone!'
  },
  {
    title: '📍 Don\'t Miss Out',
    body: 'New accommodation available near you. Open QejaConnect now!'
  }
];

function scheduleNotification() {
  const THREE_HOURS = 3 * 60 * 60 * 1000; // 3 hours in ms

  setTimeout(() => {
    fireNotification();
    // Then repeat every 3 hours
    setInterval(fireNotification, THREE_HOURS);
  }, THREE_HOURS);
}

function fireNotification() {
  // Pick a random message
  const msg = MESSAGES[Math.floor(Math.random() * MESSAGES.length)];

  self.registration.showNotification(msg.title, {
    body: msg.body,
    icon: '/QejaConnect/logo.jpg',
    badge: '/QejaConnect/logo.jpg',
    vibrate: [200, 100, 200],
    tag: 'qeja-promo', // replaces previous notification instead of stacking
    renotify: true,
    data: { url: '/QejaConnect/welcome.html' }
  });
}

// When user taps the notification, open the app
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      // If app is already open, focus it
      for (const client of clientList) {
        if (client.url.includes('/QejaConnect/') && 'focus' in client) {
          return client.focus();
        }
      }
      // Otherwise open a new window
      return clients.openWindow('/QejaConnect/welcome.html');
    })
  );
});