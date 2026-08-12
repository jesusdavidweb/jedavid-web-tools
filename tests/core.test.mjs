// tests/core.test.mjs
// Unit tests for the TypeScript Core package. The tests import the compiled
// JavaScript output to keep the suite dependency-free.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const corePath = path.resolve(__dirname, '..', 'packages', 'core', 'dist', 'index.js');
const core = require(corePath);

test('isPrivateIpv4 detects the major private ranges', () => {
  assert.equal(core.isPrivateIpv4('10.0.0.1'), true);
  assert.equal(core.isPrivateIpv4('172.20.0.1'), true);
  assert.equal(core.isPrivateIpv4('192.168.1.1'), true);
  assert.equal(core.isPrivateIpv4('127.0.0.1'), true);
  assert.equal(core.isPrivateIpv4('169.254.169.254'), true);
  assert.equal(core.isPrivateIpv4('100.64.0.1'), true);
  assert.equal(core.isPrivateIpv4('1.1.1.1'), false);
  assert.equal(core.isPrivateIpv4('8.8.8.8'), false);
});

test('isPrivateIpv6 handles loopback, ULA, mapped and 6to4', () => {
  assert.equal(core.isPrivateIpv6('::1'), true);
  assert.equal(core.isPrivateIpv6('fc00::1'), true);
  assert.equal(core.isPrivateIpv6('::ffff:10.0.0.1'), true);
  assert.equal(core.isPrivateIpv6('2002:0a00:0001::'), true);
  assert.equal(core.isPrivateIpv6('2606:4700:4700::1111'), false);
});

test('normalizeHostname strips dots and rejects garbage', () => {
  assert.equal(core.normalizeHostname('Example.com.'), 'example.com');
  assert.equal(core.normalizeHostname('0.0.0.0'), null);
  assert.equal(core.normalizeHostname('host?x'), null);
});

test('pageModel extracts a comprehensive document model', () => {
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Test</title>
    <meta name="description" content="A test page" />
    <link rel="canonical" href="https://example.com/" />
    <meta property="og:title" content="OG" />
    <link rel="preload" href="/x.css" as="style" />
  </head>
  <body>
    <main><h1>Hello</h1><img src="/a.jpg" alt="A" width="10" height="10" /></main>
    <iframe src="//x.com" title="frame"></iframe>
  </body>
</html>`;
  const m = core.pageModel(html, 'https://example.com/');
  assert.equal(m.lang, 'en');
  assert.equal(m.viewport, true);
  assert.equal(m.title, 'Test');
  assert.equal(m.canonical, 'https://example.com/');
  assert.equal(m.og.title, 'OG');
  assert.equal(m.preload.length, 1);
  assert.equal(m.headings.h1, 1);
  assert.equal(m.imageCount, 1);
  assert.equal(m.imagesMissingAlt, 0);
  assert.equal(m.iframeCount, 1);
  assert.equal(m.iframesMissingTitle, 0);
  assert.equal(m.landmarks.main, 1);
});

test('seoFindings flags missing essentials on a minimal page', () => {
  const html = '<!doctype html><html><head></head><body></body></html>';
  const m = core.pageModel(html, 'https://x.com/');
  const f = core.seoFindings(m);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('seo.title.missing'));
  assert.ok(ids.includes('seo.description.missing'));
  assert.ok(ids.includes('seo.canonical.missing'));
  assert.ok(ids.includes('seo.lang.missing'));
  assert.ok(ids.includes('seo.h1.missing'));
});

test('securityHeaderFindings flags missing critical headers', () => {
  const headers = new Headers();
  const f = core.securityHeaderFindings(headers, true);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('security.headers.content_security_policy.missing'));
  assert.ok(ids.includes('security.headers.strict_transport_security.missing'));
  assert.ok(ids.includes('security.headers.x_content_type_options.missing'));
});

test('accessibilityFindings flags missing essentials', () => {
  const html = '<!doctype html><html><head></head><body></body></html>';
  const m = core.pageModel(html, 'https://x.com/');
  const f = core.accessibilityFindings(m);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('a11y.lang'));
  assert.ok(ids.includes('a11y.title'));
  assert.ok(ids.includes('a11y.viewport'));
});

test('sortFindings orders by severity desc', () => {
  const f = [
    { id: 'a', severity: 'info', category: 'x', title: '', description: '' },
    { id: 'b', severity: 'critical', category: 'x', title: '', description: '' },
    { id: 'c', severity: 'medium', category: 'x', title: '', description: '' },
  ];
  const sorted = core.sortFindings(f);
  assert.equal(sorted[0].id, 'b');
  assert.equal(sorted[1].id, 'c');
  assert.equal(sorted[2].id, 'a');
});

test('summarizeFindings aggregates counts', () => {
  const f = [
    { id: 'a', severity: 'high', category: 'seo', title: '', description: '' },
    { id: 'b', severity: 'medium', category: 'seo', title: '', description: '' },
    { id: 'c', severity: 'medium', category: 'security', title: '', description: '' },
  ];
  const s = core.summarizeFindings(f);
  assert.equal(s.total, 3);
  assert.equal(s.bySeverity.high, 1);
  assert.equal(s.bySeverity.medium, 2);
  assert.equal(s.byCategory.seo, 2);
  assert.equal(s.byCategory.security, 1);
});
