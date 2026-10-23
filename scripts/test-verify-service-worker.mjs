import assert from 'node:assert/strict';
import { verifyServiceWorker } from './verify-service-worker.mjs';

function worker(extraPath = '', interceptApi = false) {
  return `
    const metadata = ['appearance-init.js', 'manifest.webmanifest'];
    self.addEventListener('install', event => event.waitUntil((async () => {
      const cache = await caches.open('public-shell');
      await cache.addAll([${Array.from({ length: 6 }, (_, i) => `'/_app/immutable/${i}.js'`).join(',')}
        ${extraPath ? `, '${extraPath}'` : ''}].map(path =>
          new Request(path, { credentials: 'omit' })));
    })()));
    self.addEventListener('fetch', event => {
      ${interceptApi ? 'event.respondWith(fetch(event.request));' : ''}
    });
  `;
}

await verifyServiceWorker(worker());
await assert.rejects(verifyServiceWorker(worker('/api/v1/auth/me')));
await assert.rejects(verifyServiceWorker(worker('/manifest.webmanifest')));
await assert.rejects(verifyServiceWorker(worker('', true)));
await assert.rejects(verifyServiceWorker('self.addEventListener("install", () => {});'));
console.log('Service-worker boundary regression tests passed');
