#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

export async function verifyServiceWorker(source) {
  const origin = 'https://console.example.test';
  const location = { origin, pathname: '/service-worker.js' };
  const handlers = new Map();
  const requests = [];
  class PublicRequest {
    constructor(path, options = {}) {
      Object.assign(this, { method: 'GET', mode: 'same-origin', ...options });
      this.url = new URL(path.url ?? path, origin).href;
    }
  }
  const worker = {
    location,
    addEventListener: (event, callback) => handlers.set(event, callback),
    skipWaiting: async () => {},
    clients: { claim: async () => {} },
  };
  const context = {
    self: worker, location, URL, Request: PublicRequest,
    caches: {
      open: async () => ({ addAll: async (entries) => requests.push(...entries) }),
      keys: async () => [],
      delete: async () => true,
      match: async () => undefined,
    },
    fetch: async (request) => request,
  };
  vm.runInNewContext(source, context, { timeout: 1000 });
  assert.equal(typeof handlers.get('install'), 'function');
  assert.equal(typeof handlers.get('fetch'), 'function');
  let installation;
  handlers.get('install')({ waitUntil: (promise) => { installation = promise; } });
  await installation;
  assert.ok(requests.length > 5, 'the worker must cache the public shell assets');
  for (const request of requests) {
    const url = new URL(request.url);
    assert.equal(url.origin, origin);
    assert.equal(url.search, '');
    assert.ok(url.pathname.startsWith('/_app/immutable/') ||
      /^\/icons\/[^/]+\.v1(?:[-.]|$)/u.test(url.pathname), 'only immutable public assets may be cached');
    assert.equal(request.credentials, 'omit');
  }
  for (const path of ['/api/v1/auth/me', '/', '/index.html', '/fallback.html',
    '/manifest.webmanifest', '/appearance-init.js']) {
    let intercepted = false;
    handlers.get('fetch')({
      request: new PublicRequest(path),
      respondWith: () => { intercepted = true; },
    });
    assert.equal(intercepted, false, 'mutable and authenticated requests must bypass the worker');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await verifyServiceWorker(await readFile(process.argv[2], 'utf8'));
  console.log('Service-worker cache boundaries verified');
}
