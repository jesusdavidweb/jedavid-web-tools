// tests/helpers/fixture-server.mjs
// Spin up a local HTTP fixture server for tool tests. The server binds to
// 127.0.0.1 (which the SSRF defense should accept in tests via TEST_ALLOW_LOOPBACK).

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(__dirname, '..', 'fixtures');

function readFixture(name) {
  return fs.readFileSync(path.join(fixturesDir, name), 'utf8');
}

const routes = {
  '/basic': { status: 200, contentType: 'text/html; charset=utf-8', body: readFixture('basic.html') },
  '/empty': { status: 200, contentType: 'text/html; charset=utf-8', body: readFixture('empty.html') },
  '/broken-schema': { status: 200, contentType: 'text/html; charset=utf-8', body: readFixture('broken-schema.html') },
  '/500': { status: 500, contentType: 'text/html', body: '<h1>Server error</h1>' },
  '/redirect/a': { status: 302, contentType: 'text/plain', body: 'redirecting', headers: { location: '/redirect/b' } },
  '/redirect/b': { status: 302, contentType: 'text/plain', body: 'redirecting', headers: { location: '/basic' } },
  '/loop': { status: 302, contentType: 'text/plain', body: 'looping', headers: { location: '/loop' } },
  '/secure': {
    status: 200,
    contentType: 'text/html; charset=utf-8',
    body: '<!doctype html><html><head><title>Secure</title></head><body>secure</body></html>',
    headers: {
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=63072000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'geolocation=(), camera=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-resource-policy': 'same-site',
      'x-frame-options': 'DENY',
    },
  },
  '/cookies': {
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><html><body>cookies</body></html>',
    headers: { 'set-cookie': 'sid=abc; Path=/; HttpOnly, tracking=xyz; Path=/' },
  },
  '/nextjs': {
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><html><head><title>Next</title><script src="/_next/static/chunks/main.js"></script></head><body><script>self.__NEXT_DATA__ = {}</script></body></html>',
    headers: { 'x-powered-by': 'Next.js' },
  },
  '/wordpress': {
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><html><head><title>WP</title></head><body><script src="/wp-includes/js/jquery.js"></script></body></html>',
  },
  '/robots.txt': { status: 200, contentType: 'text/plain', body: 'User-agent: *\nDisallow: /private/\nSitemap: /sitemap.xml\n' },
  '/sitemap.xml': { status: 200, contentType: 'application/xml', body: '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/</loc><lastmod>2025-01-01</lastmod></url><url><loc>https://example.com/about</loc></url></urlset>' },
  '/llms.txt': { status: 200, contentType: 'text/plain', body: '# Example\n\n> llms.txt for example.com.\n\n## Docs\n\n- [Index](https://example.com/): main entry point.\n' },
};

export function startFixtureServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const route = routes[url.pathname];
      if (!route) {
        res.statusCode = 404;
        res.setHeader('content-type', 'text/plain');
        res.end('not found');
        return;
      }
      res.statusCode = route.status;
      res.setHeader('content-type', route.contentType);
      for (const [k, v] of Object.entries(route.headers || {})) res.setHeader(k, v);
      res.end(route.body);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

export function stopFixtureServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

// Allow loopback when running tests. The runtime's assertPublic blocks
// loopback by default; tests opt in via this env var.
process.env.JEDAVID_TEST_ALLOW_LOOPBACK = '1';
