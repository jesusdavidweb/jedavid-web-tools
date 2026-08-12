// tests/html.test.mjs
// Unit tests for the HTML parsing and page model.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  tagAttrs, tags, count, first,
  pageModel, extractJsonLdBlocks, flattenJsonLd, nodeType, nodeAllTypes,
  extractAnchors,
  seoFindings, performanceFindings, accessibilityFindings, securityHeaderFindings,
  securityCookieFindings, stackFindings, indexabilityFindings, schemaFindings, linkFindings,
  llmFindings,
} from '../bin/lib/html.mjs';
import { SEVERITY } from '../bin/lib/runtime.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.resolve(__dirname, 'fixtures', name), 'utf8');

const basicHtml = fixture('basic.html');
const emptyHtml = fixture('empty.html');
const brokenHtml = fixture('broken-schema.html');

test('tagAttrs parses a single tag', () => {
  const a = tagAttrs(`<a href="/x" rel="noopener nofollow" data-flag class="link">`);
  assert.equal(a.href, '/x');
  assert.equal(a.rel, 'noopener nofollow');
  assert.equal(a['data-flag'], '');
  assert.equal(a.class, 'link');
});

test('tagAttrs handles single quotes and unquoted values', () => {
  const a = tagAttrs(`<input type='text' name=email />`);
  assert.equal(a.type, 'text');
  assert.equal(a.name, 'email');
});

test('tags finds every match', () => {
  const html = '<a href="/x">a</a><a href="/y">b</a>';
  const t = tags(html, 'a');
  assert.equal(t.length, 2);
  assert.equal(t[0].attrs.href, '/x');
  assert.equal(t[1].attrs.href, '/y');
});

test('count and first are regex helpers', () => {
  const html = '<h1>a</h1><h2>b</h2><h2>c</h2>';
  assert.equal(count(html, /<h2\b/gi), 2);
  assert.equal(first(html, /<h1[^>]*>([\s\S]*?)<\/h1>/i), 'a');
  assert.equal(first('<html></html>', /<html\b[^>]*\blang\s*=\s*["\']([^"\']+)["\']/i), null);
});

test('pageModel extracts a full basic page', () => {
  const m = pageModel(basicHtml, 'https://example.com/');
  assert.equal(m.title, 'Test Page — jedavid-web-tools fixtures');
  assert.equal(m.lang, 'en');
  assert.equal(m.canonical, 'https://example.com/');
  assert.equal(m.robots, 'index, follow');
  assert.equal(m.viewport, true);
  assert.equal(m.description.length > 0, true);
  assert.equal(m.og.title, 'Test Page');
  assert.equal(m.og.image, 'https://example.com/og.png');
  assert.equal(m.twitter.card, 'summary_large_image');
  assert.equal(m.headings.h1, 1);
  assert.equal(m.hreflangs.length, 3); // en, es, x-default
  assert.equal(m.pagination.prev, null);
  assert.equal(m.jsonLdCount, 2);
  assert.equal(m.stylesheetCount, 1);
  assert.equal(m.scriptExternal, 1);
  assert.equal(m.scriptInline, 1);
  assert.equal(m.scriptRenderBlocking, 0); // the external script has defer
  assert.equal(m.imageCount, 4);
  assert.equal(m.imagesMissingAlt, 3);
  assert.equal(m.imagesMissingDimensions, 2);
  assert.equal(m.landmarks.main, 1);
  assert.equal(m.landmarks.nav, 1);
  assert.equal(m.landmarks.header, 1);
  assert.equal(m.landmarks.footer, 1);
  assert.equal(m.skipLinks, 1);
  assert.equal(m.preload.length, 1);
  assert.equal(m.preconnect.length, 1);
  assert.equal(m.iframeCount, 2);
  assert.equal(m.iframesMissingTitle, 1);
  assert.equal(m.inputs, 2);
  assert.equal(m.labels, 1);
  assert.equal(m.buttons, 0);
});

test('pageModel handles a minimal page', () => {
  const m = pageModel(emptyHtml, 'https://example.com/');
  assert.equal(m.title, null);
  assert.equal(m.lang, null);
  assert.equal(m.canonical, null);
  assert.equal(m.headings.h1, 0);
  assert.equal(m.viewport, false);
  assert.equal(m.imageCount, 0);
});

test('extractJsonLdBlocks parses valid blocks and flags invalid ones', () => {
  const blocks = extractJsonLdBlocks(basicHtml);
  assert.equal(blocks.length, 2);
  for (const b of blocks) assert.equal(b.valid, true);
  const broken = extractJsonLdBlocks(brokenHtml);
  assert.equal(broken.length, 1);
  assert.equal(broken[0].valid, false);
  assert.match(broken[0].error, /JSON|Unexpected/);
});

test('flattenJsonLd handles @graph', () => {
  const data = { '@graph': [{ '@type': 'A' }, { '@type': 'B' }] };
  const nodes = flattenJsonLd(data);
  assert.equal(nodes.length, 2);
  assert.deepEqual(nodes.map(nodeType), ['A', 'B']);
});

test('nodeType and nodeAllTypes handle strings and arrays', () => {
  assert.equal(nodeType({ '@type': 'X' }), 'X');
  assert.equal(nodeType({ '@type': ['X', 'Y'] }), 'X');
  assert.deepEqual(nodeAllTypes({ '@type': ['X', 'Y'] }), ['X', 'Y']);
  assert.deepEqual(nodeAllTypes({}), []);
});

test('extractAnchors classifies internal vs external and nofollow', () => {
  const anchors = extractAnchors(basicHtml, 'https://example.com/');
  assert.ok(anchors.length > 0);
  const internal = anchors.filter((a) => a.internal);
  const external = anchors.filter((a) => a.internal === false);
  assert.ok(internal.length > 0);
  assert.ok(external.length > 0);
  const nofollow = anchors.find((a) => a.nofollow);
  assert.ok(nofollow);
  assert.equal(nofollow.absolute.startsWith('https://google.com'), true);
});

test('seoFindings flags the obvious gaps', () => {
  const m = pageModel(basicHtml, 'https://example.com/');
  const f = seoFindings(m);
  // basic fixture is solid; only info-level findings should be expected
  for (const finding of f) {
    assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(finding.severity));
    assert.ok(finding.id.startsWith('seo.'));
  }
});

test('seoFindings flags missing fields when the page is empty', () => {
  const m = pageModel(emptyHtml, 'https://example.com/');
  const f = seoFindings(m);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('seo.title.missing'));
  assert.ok(ids.includes('seo.description.missing'));
  assert.ok(ids.includes('seo.canonical.missing'));
  assert.ok(ids.includes('seo.lang.missing'));
  assert.ok(ids.includes('seo.h1.missing'));
});

test('performanceFindings flags a slow response', () => {
  const m = pageModel(basicHtml, 'https://example.com/');
  const headers = new Headers({});
  const f = performanceFindings(m, { responseMs: 3500, htmlBytes: 300000, headers });
  assert.ok(f.some((x) => x.id === 'perf.ttfb.slow' && x.severity === SEVERITY.HIGH));
  assert.ok(f.some((x) => x.id === 'perf.html.large'));
});

test('performanceFindings flags missing compression', () => {
  const m = pageModel(basicHtml, 'https://example.com/');
  const headers = new Headers({});
  const f = performanceFindings(m, { responseMs: 200, htmlBytes: 10_000, headers });
  assert.ok(f.some((x) => x.id === 'perf.compression.missing'));
});

test('accessibilityFindings flags missing essentials on an empty page', () => {
  const m = pageModel(emptyHtml, 'https://example.com/');
  const f = accessibilityFindings(m);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('a11y.lang'));
  assert.ok(ids.includes('a11y.title'));
  assert.ok(ids.includes('a11y.viewport'));
  assert.ok(ids.includes('a11y.landmarks.main'));
});

test('securityHeaderFindings flags missing critical headers', () => {
  const headers = new Headers({});
  const f = securityHeaderFindings(headers, true);
  const ids = f.map((x) => x.id);
  assert.ok(ids.includes('security.headers.content_security_policy.missing'));
  assert.ok(ids.includes('security.headers.strict_transport_security.missing'));
  assert.ok(ids.includes('security.headers.x_content_type_options.missing'));
});

test('securityHeaderFindings flags server version disclosure', () => {
  const headers = new Headers({ server: 'nginx/1.18.0' });
  const f = securityHeaderFindings(headers, true);
  assert.ok(f.some((x) => x.id === 'security.headers.server.disclosure'));
});

test('securityCookieFindings flags missing flags', () => {
  const cookies = [
    { name: 'session', secure: false, httpOnly: false, sameSite: null, path: '/', raw: 'session=abc' },
    { name: 'safe', secure: true, httpOnly: true, sameSite: 'Lax', path: '/', raw: 'safe=xyz; Secure; HttpOnly; SameSite=Lax' },
  ];
  const f = securityCookieFindings(cookies);
  assert.ok(f.some((x) => x.id === 'security.cookies.secure.missing' && x.title.includes('session')));
  assert.ok(f.some((x) => x.id === 'security.cookies.httponly.missing' && x.title.includes('session')));
  assert.ok(f.some((x) => x.id === 'security.cookies.samesite.missing' && x.title.includes('session')));
  // safe cookie has no findings
  assert.equal(f.some((x) => x.title.includes('safe')), false);
});

test('stackFindings detects WordPress and Next.js from signatures', () => {
  const wp = stackFindings('<html><body><script src="/wp-includes/js/jquery.js"></script></body></html>', new Headers({}));
  assert.ok(wp.some((s) => s.name === 'WordPress'));
  const nx = stackFindings('<html><body><script>self.__NEXT_DATA__ = {}</script><script src="/_next/static/chunks/main.js"></script></body></html>', new Headers({ 'x-powered-by': 'Next.js' }));
  assert.ok(nx.some((s) => s.name === 'Next.js'));
});

test('stackFindings detects CDN by header', () => {
  const cf = stackFindings('<html></html>', new Headers({ 'cf-ray': '12345', 'cf-cache-status': 'HIT' }));
  assert.ok(cf.some((s) => s.name === 'Cloudflare'));
  const vercel = stackFindings('<html></html>', new Headers({ 'x-vercel-id': 'abc' }));
  assert.ok(vercel.some((s) => s.name === 'Vercel'));
  const netlify = stackFindings('<html></html>', new Headers({ 'x-nf-request-id': 'abc' }));
  assert.ok(netlify.some((s) => s.name === 'Netlify'));
});

test('indexabilityFindings flags noindex meta', () => {
  const f = indexabilityFindings({ status: 200, robotsMeta: 'noindex, nofollow', xRobotsTag: null, canonical: null, robotsTxt: null, finalUrl: 'https://x.com/' });
  assert.ok(f.some((x) => x.id === 'indexability.noindex.meta'));
});

test('linkFindings flags empty anchor text', () => {
  const f = linkFindings([
    { href: '/a', text: 'A', internal: true, nofollow: false },
    { href: '/b', text: '', internal: true, nofollow: false },
  ]);
  assert.ok(f.some((x) => x.id === 'links.empty_text'));
});

test('schemaFindings flags invalid JSON-LD', () => {
  const f = schemaFindings([{ raw: 'not json', valid: false, error: 'bad' }]);
  assert.ok(f.some((x) => x.id === 'schema.invalid'));
});

test('llmFindings flags missing llms.txt and structured data', () => {
  const f = llmFindings({ llmsTxt: { present: false }, robotsTxt: null, jsonLd: [], model: { lang: null, description: null } });
  assert.ok(f.some((x) => x.id === 'llm.llms_txt.missing'));
  assert.ok(f.some((x) => x.id === 'llm.structured.missing'));
});
