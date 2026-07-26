// Panoplia service worker — minimal app-shell caching for instant loads.
//
// Strategy: precache the script + icons + manifest + landing page shell
// at install time. At runtime, network-first for navigations (so we
// always get the freshest login state and redirect logic), with a
// cached fallback to the shell when offline. Static assets use
// cache-first.
//
// This is intentionally small — Panoplia is a launcher into OTHER
// apps, so the work happens in the upstream apps. We don't cache
// responses from /api/admin/* or /auth/* at all.

const CACHE_VERSION = "v1";
const APP_SHELL = [
  "/",
  "/login",
  "/static/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/icon-512-maskable.png",
  "/static/icons/apple-touch-icon.png",
  "/static/icons/favicon-32.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(`panoplia-${CACHE_VERSION}`).then((cache) =>
      cache.addAll(APP_SHELL).catch((err) => {
        // Don't fail install if a single asset is missing — log and continue.
        console.warn("[panoplia-sw] cache.addAll partial failure:", err);
      })
    )
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== `panoplia-${CACHE_VERSION}`)
          .map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Never cache auth, admin, or API calls — those must always be live.
  if (
    url.pathname.startsWith("/auth/") ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/admin/")
  ) {
    return;
  }

  // Navigations: network-first, fall back to cached shell when offline.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          // Best-effort cache update for the shell pages
          const copy = res.clone();
          caches.open(`panoplia-${CACHE_VERSION}`).then((cache) =>
            cache.put(req, copy).catch(() => {})
          );
          return res;
        })
        .catch(() =>
          caches.match(req).then((cached) => cached || caches.match("/"))
        )
    );
    return;
  }

  // Static assets: cache-first.
  if (
    url.pathname.startsWith("/static/") ||
    url.pathname.startsWith("/icons/")
  ) {
    event.respondWith(
      caches.match(req).then(
        (cached) =>
          cached ||
          fetch(req).then((res) => {
            const copy = res.clone();
            caches.open(`panoplia-${CACHE_VERSION}`).then((cache) =>
              cache.put(req, copy).catch(() => {})
            );
            return res;
          })
      )
    );
  }
});
