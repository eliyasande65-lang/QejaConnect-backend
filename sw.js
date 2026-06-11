// QejaConnect Service Worker v3
const STATIC_CACHE = 'qeja-static-v3';
const IMAGES_CACHE = 'qeja-images-v3';
const API_CACHE    = 'qeja-api-v3';

const CORE_ASSETS = [
  "/QejaConnect/welcome.html",
  "/QejaConnect/offline.html",
  "/QejaConnect/login.html",
  "/QejaConnect/tenant.html",
  "/QejaConnect/host.html",
  "/QejaConnect/home.html",
  "/QejaConnect/landlords.html",
  "/QejaConnect/hostdashboard.html",
  "/QejaConnect/contact.html",
  "/QejaConnect/logo.jpg",
  "/QejaConnect/logo-192.png",
  "/QejaConnect/logo-512.png",
  "/QejaConnect/manifest.json"
];

// ── Install: pre-cache core assets ──────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ───────────────────────────────────────────
self.addEventListener('activate', event => {
  const valid = [STATIC_CACHE, IMAGES_CACHE, API_CACHE];
  event.waitUntil(
    caches.keys()
      .then(keys =>
        Promise.all(
          keys.filter(k => !valid.includes(k)).map(k => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

// ── Fetch: route to the right strategy ──────────────────────────────────────
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // 1. Images — cache first, fallback to network, store on miss
  if (
    event.request.destination === 'image' ||
    /\.(jpg|jpeg|png|webp|gif|svg)(\?.*)?$/i.test(url.pathname)
  ) {
    event.respondWith(
      caches.open(IMAGES_CACHE).then(async cache => {
        const cached = await cache.match(event.request);
        if (cached) return cached;
        try {
          const response = await fetch(event.request);
          if (response.ok) cache.put(event.request, response.clone());
          return response;
        } catch {
          // No fallback image available — return empty 404
          return new Response('', { status: 404, statusText: 'Not Found' });
        }
      })
    );
    return;
  }

  // 2. API calls (/properties, /updates) — network first, fallback to cache
  if (
    url.hostname === 'qeja-backend-azkf.onrender.com' &&
    (url.pathname.startsWith('/properties') || url.pathname.startsWith('/updates'))
  ) {
    event.respondWith(
      caches.open(API_CACHE).then(async cache => {
        try {
          const response = await fetch(event.request);
          if (response.ok) cache.put(event.request, response.clone());
          return response;
        } catch {
          const cached = await cache.match(event.request);
          return cached || new Response(
            JSON.stringify({ success: false, message: 'You are offline' }),
            { status: 503, headers: { 'Content-Type': 'application/json' } }
          );
        }
      })
    );
    return;
  }

  // 3. QejaConnect pages & assets — network first, fallback to cache, then offline page
  event.respondWith(
    fetch(event.request)
      .then(response => {
        if (response.ok && url.pathname.startsWith('/QejaConnect/')) {
          caches.open(STATIC_CACHE)
            .then(cache => cache.put(event.request, response.clone()));
        }
        return response;
      })
      .catch(async () => {
        const cached = await caches.match(event.request);
        if (cached) return cached;
        // HTML navigation fallback
        const accept = event.request.headers.get('Accept') || '';
        if (accept.includes('text/html')) {
          return caches.match('/QejaConnect/offline.html');
        }
      })
  );
});