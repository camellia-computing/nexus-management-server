/// <reference lib="webworker" />

import { build, files, version } from '$service-worker';

const worker = self as unknown as ServiceWorkerGlobalScope;
const cachePrefix = 'camellia-console-shell-';
const cacheName = `${cachePrefix}${version}`;
const normalizePath = (path: string) => (path.startsWith('/') ? path : `/${path}`);
const shellPaths = [...build, ...files]
  .map(normalizePath)
  .filter(
    (path) =>
      path.startsWith('/_app/immutable/') || (path.startsWith('/icons/') && path.includes('.v1'))
  );
const allowedPaths = new Set(shellPaths);

worker.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(cacheName);
      await cache.addAll(
        shellPaths.map(
          (path) => new Request(path, { cache: 'reload', credentials: 'omit', mode: 'same-origin' })
        )
      );
      await worker.skipWaiting();
    })()
  );
});

worker.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((key) => key.startsWith(cachePrefix) && key !== cacheName)
          .map((key) => caches.delete(key))
      );
      await worker.clients.claim();
    })()
  );
});

worker.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (
    request.method !== 'GET' ||
    request.mode === 'navigate' ||
    url.origin !== worker.location.origin ||
    url.search !== '' ||
    !allowedPaths.has(url.pathname)
  ) {
    return;
  }
  event.respondWith(
    (async () => {
      const cached = await caches.match(request);
      if (cached) return cached;
      return fetch(new Request(request, { credentials: 'omit' }));
    })()
  );
});
