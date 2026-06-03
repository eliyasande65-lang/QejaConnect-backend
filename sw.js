// JavaScript source code
// QejaConnect Service Worker v2
const CACHE_NAME = 'qejaconnect-v2';

const CORE_ASSETS = [
  "/QejaConnect/welcome.html",
  "/QejaConnect/offline.html",
  "/QejaConnect/logo.jpg",
  "/QejaConnect/manifest.json"
  "/QejaConnect/login.html",
  "/QejaConnect/tenant.html",
  "/QejaConnect/host.html",
  "/QejaConnect/landlords.html",
  "/QejaConnect/hostdashboard.html",
  "/QejaConnect/contact.html",
  "/QejaConnect/logo.jpg",
  "/QejaConnect/logo-192.png",
  "/QejaConnect/logo-512.png",
  "/QejaConnect/manifest.json"
];

// Install: cache core assets including offline page
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

// Fetch: network first, fall back to cache, then offline page
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Cache successful responses for pages in our scope
        if (response.ok && event.request.url.includes('/QejaConnect/')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => {
        // Offline — try cache first
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          // If it's an HTML page request, show offline page
          if (event.request.headers.get('Accept').includes('text/html')) {
            return caches.match('/QejaConnect/offline.html');
          }
        });
      })
  );f
});