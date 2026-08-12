// packages/core/src/index.ts
// Shared analysis library for jedavid-web-tools.
//
// The Core exposes the typed primitives used by the development MCP server
// and the CLI. The portable runtime in `bin/` re-implements the same
// behaviour in dependency-free JS; the contract is verified by the test
// suite under `tests/`.

import * as cheerio from 'cheerio';
import { lookup } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';

// ---------------- Types ----------------------------------------------------

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type FindingCategory =
  | 'performance'
  | 'seo'
  | 'accessibility'
  | 'security'
  | 'indexability'
  | 'llm'
  | 'crawlability'
  | 'stack'
  | 'links'
  | 'http'
  | 'schema';

export interface Finding {
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  description: string;
  evidence?: string | Record<string, unknown>;
  recommendation?: string;
}

export interface Evidence {
  type: 'http' | 'html' | 'header' | 'meta' | 'dns' | 'redirect' | 'asset' | 'api' | 'config';
  summary: string;
  data?: unknown;
}

export interface ToolResult<T = unknown> {
  ok: boolean;
  tool: string;
  target: string;
  summary: {
    total?: number;
    bySeverity?: Partial<Record<Severity, number>>;
    byCategory?: Partial<Record<FindingCategory, number>>;
    [key: string]: unknown;
  };
  findings: Finding[];
  evidence: Evidence[];
  metadata: {
    fetchedAt: string;
    durationMs: number;
    version: string;
    [key: string]: unknown;
  };
  data: T;
}

export interface AuditOptions {
  categories?: FindingCategory[];
  timeoutMs?: number;
  userAgent?: string;
}

export interface PageModel {
  title: string | null;
  description: string | null;
  keywords: string | null;
  author: string | null;
  generator: string | null;
  themeColor: string | null;
  canonical: string | null;
  amphtml: string | null;
  lang: string | null;
  robots: string | null;
  googlebot: string | null;
  viewport: boolean;
  og: Record<string, string | null>;
  twitter: Record<string, string | null>;
  hreflangs: Array<{ lang: string; href: string }>;
  pagination: { prev: string | null; next: string | null };
  preload: string[];
  preconnect: string[];
  modulepreload: string[];
  dnsPrefetch: string[];
  headings: Record<'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6', number>;
  images: Array<{
    src: string | null;
    alt: string | null;
    width: string | null;
    height: string | null;
    loading: string | null;
    decoding: string | null;
    fetchpriority: string | null;
    srcset: string | null;
    sizes: string | null;
  }>;
  imageCount: number;
  imagesMissingAlt: number;
  imagesMissingDimensions: number;
  imagesLazy: number;
  scripts: Array<{
    src: string | null;
    type: string | null;
    async: boolean;
    defer: boolean;
    inline: boolean;
    jsonLd: boolean;
  }>;
  scriptCount: number;
  scriptExternal: number;
  scriptInline: number;
  scriptRenderBlocking: number;
  stylesheetCount: number;
  stylesheetHrefs: string[];
  inlineStyles: number;
  iframes: Array<{ src: string | null; title: string | null }>;
  iframeCount: number;
  iframesMissingTitle: number;
  jsonLdCount: number;
  microdataCount: number;
  rdfaCount: number;
  forms: number;
  inputs: number;
  labels: number;
  buttons: number;
  landmarks: {
    main: number;
    nav: number;
    header: number;
    footer: number;
    aside: number;
    section: number;
    article: number;
  };
  skipLinks: number;
}

export interface AuditResult {
  url: string;
  finalUrl: string;
  status: number;
  fetchedAt: string;
  timing: { responseMs: number; ttfbMs: number };
  document: PageModel;
  headers: Record<string, string>;
  findings: Finding[];
  summary: { errors: number; warnings: number; info: number; byCategory: Record<string, number> };
}

// ---------------- Constants ------------------------------------------------

const VERSION = '0.3.0';
const DEFAULT_CATEGORIES: FindingCategory[] = ['performance', 'seo', 'security'];
const UA = `jedavid-web-tools/${VERSION} (+https://github.com/jesusdavidweb/jedavid-web-tools)`;
const MAX_HTML = 2_500_000;
const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

// ---------------- SSRF defense --------------------------------------------

export function isPrivateIpv4(ip: string): boolean {
  if (!ip) return true;
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const o = parts.map((n) => Number(n));
  if (o.some((v) => !Number.isInteger(v) || v < 0 || v > 255)) return true;
  const [a, b, c, d] = o as number[];
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 18 && c < 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224 && a <= 239) return true;
  if (a >= 240) return true;
  return false;
}

export function isPrivateIpv6(ip: string): boolean {
  if (!ip) return true;
  const lower = ip.toLowerCase().split('%')[0];
  if (lower === '::' || lower === '::1') return true;
  if (lower === '::ffff:0:0' || lower === '64:ff9b::' || lower === '64:ff9b:1::') return true;
  const mapped = lower.match(/^::ffff:([0-9.]+)$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  const sixToFour = lower.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})/);
  if (sixToFour) {
    const hi = parseInt(sixToFour[1].padStart(4, '0'), 16);
    const lo = parseInt(sixToFour[2].padStart(4, '0'), 16);
    const a = (hi >> 8) & 0xff;
    const b = hi & 0xff;
    const c = (lo >> 8) & 0xff;
    const d = lo & 0xff;
    if (isPrivateIpv4(`${a}.${b}.${c}.${d}`)) return true;
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe80:') || /^(fe8|fe9|fea|feb)/.test(lower)) return true;
  if (lower.startsWith('ff')) return true;
  if (lower.startsWith('2001:db8')) return true;
  if (lower.startsWith('2001::') && lower.length <= 8) return true;
  return false;
}

export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  return ip.includes(':') ? isPrivateIpv6(ip) : isPrivateIpv4(ip);
}

export function normalizeHostname(input: string): string | null {
  if (typeof input !== 'string') return null;
  let host = input.trim().toLowerCase();
  if (!host) return null;
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host === '0' || host === '0.0.0.0' || !host) return null;
  if (/[\s/?#]/.test(host)) return null;
  return host;
}

const lookupCache = new Map<string, string[]>();
async function resolvePublic(host: string): Promise<boolean> {
  let addresses = lookupCache.get(host);
  if (!addresses) {
    const result = await lookup(host, { all: true });
    addresses = result.map((r) => r.address);
    lookupCache.set(host, addresses);
  }
  if (!addresses.length) return false;
  return !addresses.some((a) => isPrivateIp(a));
}

export async function assertPublic(url: URL): Promise<void> {
  if (process.env.JEDAVID_TEST_ALLOW_LOOPBACK === '1') {
    if (url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === 'localhost') return;
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP(S) URLs are supported.');
  const host = normalizeHostname(url.hostname);
  if (!host) throw new Error('Invalid hostname.');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('Localhost and local network hostnames are blocked.');
  }
  if (/^[0-9.]+$/.test(host) || host.includes(':')) {
    if (isPrivateIp(host)) throw new Error('Private/local network targets are blocked.');
    return;
  }
  if (!(await resolvePublic(host))) throw new Error('Private/local network targets are blocked.');
}

// ---------------- HTTP helpers --------------------------------------------

export interface SafeFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxRedirects?: number;
  maxBytes?: number;
}

export async function safeFetch(input: string, options: SafeFetchOptions = {}): Promise<{ response: Response; responseMs: number; ttfbMs: number; url: URL; redirected: number; }> {
  const { method = 'GET', headers = {}, timeoutMs = 15_000, maxRedirects = 5, body } = options;
  let url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
  let redirected = 0;
  for (let i = 0; i <= maxRedirects; i++) {
    await assertPublic(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = performance.now();
    let firstByte = 0;
    let response: Response;
    try {
      response = await fetch(url, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': UA, accept: '*/*', ...headers },
        ...(body !== undefined ? { body } : {}),
      });
      firstByte = performance.now();
      // Eagerly drain so we can read ttfb vs total time.
      await response.arrayBuffer();
    } finally { clearTimeout(timer); }
    const responseMs = Math.round(performance.now() - started);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const loc = response.headers.get('location');
      if (!loc) return { response, responseMs, ttfbMs: Math.round(firstByte - started), url, redirected };
      if (i === maxRedirects) throw new Error('Too many redirects.');
      const next = new URL(loc, url);
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new Error('Redirect to a non-HTTP(S) target is blocked.');
      }
      url = next;
      redirected = i + 1;
      continue;
    }
    return { response, responseMs, ttfbMs: Math.round(firstByte - started), url, redirected };
  }
  throw new Error('Unable to fetch URL.');
}

export async function fetchText(input: string, options: SafeFetchOptions = {}) {
  const result = await safeFetch(input, { ...options, headers: { accept: 'text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.5', ...(options.headers || {}) } });
  const text = await result.response.text();
  if (Buffer.byteLength(text) > MAX_HTML) throw new Error(`Response exceeds ${MAX_HTML} bytes.`);
  return { ...result, text };
}

// ---------------- Page model (cheerio-backed) ------------------------------

export function pageModel(html: string, base: URL | string): PageModel {
  const baseUrl = typeof base === 'string' ? new URL(base) : base;
  const $ = cheerio.load(html);

  const meta = (name: string) => $(`meta[name="${name}"]`).first().attr('content')?.trim() || null;
  const metaProperty = (prop: string) => $(`meta[property="${prop}"]`).first().attr('content')?.trim() || null;

  const canonical = $('link[rel="canonical"]').first().attr('href')?.trim() || null;
  const amphtml = $('link[rel="amphtml"]').first().attr('href')?.trim() || null;
  const hreflangs = $('link[hreflang]').map((_, el) => ({
    lang: $(el).attr('hreflang') || '',
    href: $(el).attr('href') || '',
  })).get();

  const images = $('img').map((_, el) => ({
    src: $(el).attr('src') || null,
    alt: $(el).attr('alt') ?? null,
    width: $(el).attr('width') || null,
    height: $(el).attr('height') || null,
    loading: $(el).attr('loading') || null,
    decoding: $(el).attr('decoding') || null,
    fetchpriority: $(el).attr('fetchpriority') || null,
    srcset: $(el).attr('srcset') || null,
    sizes: $(el).attr('sizes') || null,
  })).get();

  const scripts = $('script').map((_, el) => {
    const $s = $(el);
    const src = $s.attr('src') || null;
    const type = $s.attr('type') || null;
    return {
      src,
      type,
      async: $s.is('[async]'),
      defer: $s.is('[defer]'),
      inline: !src,
      jsonLd: (type || '').toLowerCase() === 'application/ld+json',
    };
  }).get();

  const iframes = $('iframe').map((_, el) => ({
    src: $(el).attr('src') || null,
    title: $(el).attr('title') || null,
  })).get();

  return {
    title: $('title').first().text().trim() || null,
    description: meta('description'),
    keywords: meta('keywords'),
    author: meta('author'),
    generator: meta('generator'),
    themeColor: meta('theme-color'),
    canonical,
    amphtml,
    lang: $('html').first().attr('lang')?.trim() || null,
    robots: meta('robots'),
    googlebot: meta('googlebot'),
    viewport: $('meta[name="viewport"]').length > 0,
    og: {
      title: metaProperty('og:title'),
      description: metaProperty('og:description'),
      image: metaProperty('og:image'),
      url: metaProperty('og:url'),
      type: metaProperty('og:type'),
      site_name: metaProperty('og:site_name'),
      locale: metaProperty('og:locale'),
    },
    twitter: {
      card: metaProperty('twitter:card') || meta('twitter:card'),
      title: metaProperty('twitter:title') || meta('twitter:title'),
      description: metaProperty('twitter:description') || meta('twitter:description'),
      image: metaProperty('twitter:image') || meta('twitter:image'),
      site: metaProperty('twitter:site') || meta('twitter:site'),
    },
    hreflangs,
    pagination: {
      prev: $('link[rel="prev"]').first().attr('href')?.trim() || null,
      next: $('link[rel="next"]').first().attr('href')?.trim() || null,
    },
    preload: $('link[rel="preload"]').map((_, el) => $(el).attr('href') || '').get().filter(Boolean),
    preconnect: $('link[rel="preconnect"]').map((_, el) => $(el).attr('href') || '').get().filter(Boolean),
    modulepreload: $('link[rel="modulepreload"]').map((_, el) => $(el).attr('href') || '').get().filter(Boolean),
    dnsPrefetch: $('link[rel="dns-prefetch"]').map((_, el) => $(el).attr('href') || '').get().filter(Boolean),
    headings: {
      h1: $('h1').length,
      h2: $('h2').length,
      h3: $('h3').length,
      h4: $('h4').length,
      h5: $('h5').length,
      h6: $('h6').length,
    },
    images,
    imageCount: images.length,
    imagesMissingAlt: images.filter((i) => i.alt === null).length,
    imagesMissingDimensions: images.filter((i) => !i.width || !i.height).length,
    imagesLazy: images.filter((i) => (i.loading || '').toLowerCase() === 'lazy').length,
    scripts,
    scriptCount: scripts.length,
    scriptExternal: scripts.filter((s) => s.src).length,
    scriptInline: scripts.filter((s) => s.inline && !s.jsonLd).length,
    scriptRenderBlocking: scripts.filter((s) => s.src && !s.async && !s.defer).length,
    stylesheetCount: $('link[rel="stylesheet"]').length,
    stylesheetHrefs: $('link[rel="stylesheet"]').map((_, el) => $(el).attr('href') || '').get().filter(Boolean),
    inlineStyles: $('style').length,
    iframes,
    iframeCount: iframes.length,
    iframesMissingTitle: iframes.filter((f) => !f.title).length,
    jsonLdCount: scripts.filter((s) => s.jsonLd).length,
    microdataCount: $('[itemtype]').length,
    rdfaCount: $('[typeof]').length,
    forms: $('form').length,
    inputs: $('input').length,
    labels: $('label').length,
    buttons: $('button').length,
    landmarks: {
      main: $('main, [role="main"]').length,
      nav: $('nav, [role="navigation"]').length,
      header: $('header, [role="banner"]').length,
      footer: $('footer, [role="contentinfo"]').length,
      aside: $('aside, [role="complementary"]').length,
      section: $('section').length,
      article: $('article').length,
    },
    skipLinks: $('a[href^="#"]').filter((_, el) => /skip|jump to|go to/i.test($(el).text())).length,
  };
}

// ---------------- Findings helpers -----------------------------------------

function f(partial: Omit<Finding, never>): Finding { return partial; }

export function seoFindings(m: PageModel): Finding[] {
  const out: Finding[] = [];
  if (!m.title) out.push(f({ id: 'seo.title.missing', severity: 'medium', category: 'seo', title: 'Missing <title>', description: 'The page has no non-empty <title>.', recommendation: 'Add a unique, descriptive title (50-60 characters is a common heuristic).' }));
  else if (m.title.length > 65) out.push(f({ id: 'seo.title.long', severity: 'low', category: 'seo', title: 'Long title', description: `Title is ${m.title.length} characters.`, recommendation: 'Trim under 60 characters so it is not truncated in search results.' }));
  if (!m.description) out.push(f({ id: 'seo.description.missing', severity: 'low', category: 'seo', title: 'Missing meta description', description: 'No meta description was found.', recommendation: 'Add a page-specific description of 120-160 characters.' }));
  if (!m.canonical) out.push(f({ id: 'seo.canonical.missing', severity: 'low', category: 'seo', title: 'Missing canonical', description: 'No <link rel="canonical"> was found.', recommendation: 'Add a self-referencing or intentionally consolidated canonical URL.' }));
  if (!m.lang) out.push(f({ id: 'seo.lang.missing', severity: 'low', category: 'seo', title: 'Missing html[lang]', description: 'The root html element has no lang attribute.', recommendation: 'Declare the page language.' }));
  if (m.headings.h1 === 0) out.push(f({ id: 'seo.h1.missing', severity: 'medium', category: 'seo', title: 'Missing H1', description: 'No H1 was found on the page.', recommendation: 'Use a clear primary heading that describes the page topic.' }));
  else if (m.headings.h1 > 1) out.push(f({ id: 'seo.h1.multiple', severity: 'info', category: 'seo', title: 'Multiple H1 headings', description: `${m.headings.h1} H1 headings were found.`, recommendation: 'Verify the heading hierarchy communicates a clear primary topic.' }));
  if (m.robots && /\bnoindex\b/i.test(m.robots)) out.push(f({ id: 'seo.robots.noindex', severity: 'medium', category: 'seo', title: 'Page is marked noindex', description: `robots meta: ${m.robots}`, recommendation: 'Confirm that excluding this URL from indexing is intentional.' }));
  if (!m.og.title) out.push(f({ id: 'seo.og.missing', severity: 'low', category: 'seo', title: 'Open Graph metadata missing', description: 'No og:title was found.', recommendation: 'Add at minimum og:title, og:description, og:image and og:url.' }));
  if (!m.og.image) out.push(f({ id: 'seo.og.image.missing', severity: 'low', category: 'seo', title: 'Open Graph image missing', description: 'No og:image was found.', recommendation: 'Add an og:image (1200x630 is a common safe size).' }));
  if (!m.twitter.card) out.push(f({ id: 'seo.twitter.missing', severity: 'low', category: 'seo', title: 'Twitter Card metadata missing', description: 'No twitter:card was found.', recommendation: 'Add at minimum twitter:card, twitter:title, twitter:description and twitter:image.' }));
  if (m.jsonLdCount === 0 && m.microdataCount === 0 && m.rdfaCount === 0) out.push(f({ id: 'seo.structured.missing', severity: 'info', category: 'seo', title: 'No structured data found', description: 'No JSON-LD, Microdata or RDFa was detected.', recommendation: 'Add structured data when it accurately represents visible content.' }));
  if (m.imagesMissingAlt > 0) out.push(f({ id: 'seo.images.alt.missing', severity: 'medium', category: 'seo', title: 'Images without alt', description: `${m.imagesMissingAlt} of ${m.imageCount} images lack alt attributes.`, recommendation: 'Add descriptive alt text or alt="" for decorative images.' }));
  return out;
}

export function performanceFindings(m: PageModel, timing: { responseMs: number; ttfbMs: number }, htmlBytes: number, headers: Headers): Finding[] {
  const out: Finding[] = [];
  if (timing.responseMs > 1000) out.push(f({ id: 'perf.ttfb.slow', severity: timing.responseMs > 2000 ? 'high' : 'medium', category: 'performance', title: 'Slow document response', description: `Initial response took ${timing.responseMs} ms (TTFB ${timing.ttfbMs} ms).`, recommendation: 'Inspect origin latency, caching, server-side work and edge delivery.' }));
  if (htmlBytes > 200_000) out.push(f({ id: 'perf.html.large', severity: htmlBytes > 500_000 ? 'high' : 'medium', category: 'performance', title: 'Large HTML document', description: `HTML response is ${(htmlBytes / 1024).toFixed(1)} KiB.`, recommendation: 'Reduce oversized inline payloads and duplicated markup.' }));
  if (m.scriptExternal > 20) out.push(f({ id: 'perf.scripts.many', severity: 'medium', category: 'performance', title: 'High script count', description: `${m.scriptExternal} external scripts were found.`, recommendation: 'Audit third-party scripts and bundle critical code.' }));
  if (m.scriptRenderBlocking > 0) out.push(f({ id: 'perf.scripts.render_blocking', severity: 'medium', category: 'performance', title: 'Render-blocking scripts', description: `${m.scriptRenderBlocking} external scripts in the head without async or defer.`, recommendation: 'Add async or defer, or move them to the end of body.' }));
  if (m.imageCount > 0 && m.imagesLazy === m.imageCount) out.push(f({ id: 'perf.images.all_lazy', severity: 'medium', category: 'performance', title: 'Every image is lazy-loaded', description: 'All images use loading="lazy", which can delay the above-the-fold LCP image.', recommendation: 'Avoid lazy-loading the primary above-the-fold image; consider fetchpriority="high".' }));
  if (m.imagesMissingDimensions > 0) out.push(f({ id: 'perf.images.cls', severity: 'medium', category: 'performance', title: 'Images without explicit dimensions', description: `${m.imagesMissingDimensions} images do not declare width and height.`, recommendation: 'Reserve intrinsic aspect ratio to reduce CLS.' }));
  if (!m.viewport) out.push(f({ id: 'perf.viewport.missing', severity: 'high', category: 'performance', title: 'Missing viewport meta', description: 'No viewport meta tag was found.', recommendation: 'Add a responsive viewport declaration for mobile rendering.' }));
  if (m.preload.length === 0 && (m.scriptExternal > 0 || m.stylesheetCount > 0)) out.push(f({ id: 'perf.preload.missing', severity: 'info', category: 'performance', title: 'No resource hints', description: 'No rel="preload" was used.', recommendation: 'Preload critical above-the-fold assets and fonts.' }));
  if (!headers.get('content-encoding') && htmlBytes > 5_000) out.push(f({ id: 'perf.compression.missing', severity: 'medium', category: 'performance', title: 'No content compression', description: 'Response does not advertise content-encoding.', recommendation: 'Enable gzip, brotli or zstd at the origin or edge.' }));
  return out;
}

export function securityHeaderFindings(headers: Headers, isHttps: boolean): Finding[] {
  const out: Finding[] = [];
  const check = (name: string, label: string, severity: Severity, rec?: string) => {
    if (!headers.has(name)) out.push(f({ id: `security.headers.${name.replace(/-/g, '_')}.missing`, severity, category: 'security', title: `Missing ${label}`, description: `Response does not include ${label}.`, recommendation: rec || `Define an appropriate ${label} policy and test it before enforcing broadly.` }));
  };
  check('content-security-policy', 'Content-Security-Policy', 'medium', 'Define a strict CSP starting with a report-only deployment.');
  if (isHttps) check('strict-transport-security', 'Strict-Transport-Security', 'medium', 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload once verified.');
  check('x-content-type-options', 'X-Content-Type-Options', 'medium', 'Send X-Content-Type-Options: nosniff.');
  check('referrer-policy', 'Referrer-Policy', 'low', 'Send Referrer-Policy: strict-origin-when-cross-origin or stricter.');
  check('permissions-policy', 'Permissions-Policy', 'low', 'Lock down powerful features (camera, microphone, geolocation, etc.).');
  check('cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', 'low');
  check('cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', 'info');
  check('cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', 'info');
  check('x-frame-options', 'X-Frame-Options', 'low', 'Add frame-ancestors in CSP and/or X-Frame-Options: DENY where appropriate.');
  const server = headers.get('server');
  if (server && /\d/.test(server)) out.push(f({ id: 'security.headers.server.disclosure', severity: 'low', category: 'security', title: 'Server version disclosure', description: `Server: ${server}`, recommendation: 'Avoid leaking server version details.' }));
  const powered = headers.get('x-powered-by');
  if (powered) out.push(f({ id: 'security.headers.x_powered_by', severity: 'low', category: 'security', title: 'X-Powered-By disclosure', description: `X-Powered-By: ${powered}`, recommendation: 'Remove the X-Powered-By header.' }));
  return out;
}

export function accessibilityFindings(m: PageModel): Finding[] {
  const out: Finding[] = [];
  if (!m.lang) out.push(f({ id: 'a11y.lang', severity: 'medium', category: 'accessibility', title: 'Missing html[lang]', description: 'Root html element has no lang attribute.', recommendation: 'Declare the page language.' }));
  if (!m.title) out.push(f({ id: 'a11y.title', severity: 'high', category: 'accessibility', title: 'Missing document title', description: 'A non-empty <title> is required for orientation.', recommendation: 'Add a descriptive, unique page title.' }));
  if (!m.viewport) out.push(f({ id: 'a11y.viewport', severity: 'high', category: 'accessibility', title: 'Missing viewport meta', description: 'Without a viewport meta tag the page is not mobile-accessible.', recommendation: 'Add a responsive viewport declaration.' }));
  if (m.headings.h1 === 0) out.push(f({ id: 'a11y.h1', severity: 'medium', category: 'accessibility', title: 'Missing H1', description: 'A single H1 helps establish page structure for assistive technology.', recommendation: 'Use a clear primary heading.' }));
  if (m.imagesMissingAlt > 0) out.push(f({ id: 'a11y.images.alt', severity: 'medium', category: 'accessibility', title: 'Images without alt', description: `${m.imagesMissingAlt} images do not declare alt.`, recommendation: 'Provide alt text or alt="" for decorative images.' }));
  if (m.inputs > 0 && m.labels === 0) out.push(f({ id: 'a11y.forms.labels', severity: 'medium', category: 'accessibility', title: 'Inputs without labels', description: `Found ${m.inputs} inputs but no <label> elements.`, recommendation: 'Use <label for="id"> or aria-label to associate a label with every input.' }));
  if (m.iframesMissingTitle > 0) out.push(f({ id: 'a11y.iframes.title', severity: 'medium', category: 'accessibility', title: 'Iframes without title', description: `${m.iframesMissingTitle} iframe(s) do not declare a title attribute.`, recommendation: 'Add a descriptive title to every iframe.' }));
  if (m.landmarks.main === 0) out.push(f({ id: 'a11y.landmarks.main', severity: 'low', category: 'accessibility', title: 'No <main> landmark', description: 'A <main> landmark helps screen reader users skip to primary content.', recommendation: 'Wrap the primary content in a <main> element.' }));
  if (m.landmarks.nav === 0) out.push(f({ id: 'a11y.landmarks.nav', severity: 'low', category: 'accessibility', title: 'No <nav> landmark', description: 'A <nav> landmark helps screen reader users find navigation.', recommendation: 'Wrap primary navigation in a <nav> element.' }));
  if (m.skipLinks === 0) out.push(f({ id: 'a11y.skip_link', severity: 'low', category: 'accessibility', title: 'No skip navigation link', description: 'No "skip to content" link was detected.', recommendation: 'Provide a skip link as the first focusable element.' }));
  return out;
}

// ---------------- Audit orchestration --------------------------------------

export async function auditSite(input: string, options: AuditOptions = {}): Promise<AuditResult> {
  const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
  const categories = options.categories?.length ? options.categories : DEFAULT_CATEGORIES;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 20_000);
  const started = performance.now();
  let response: Response;
  try {
    response = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': options.userAgent ?? UA,
        accept: 'text/html,application/xhtml+xml',
      },
    });
  } finally { clearTimeout(timeout); }
  const responseMs = Math.round(performance.now() - started);
  const html = await response.text();
  const htmlBytes = Buffer.byteLength(html);
  const document = pageModel(html, response.url);

  const findings: Finding[] = [];
  if (!response.ok) findings.push(f({ id: 'http.error', severity: 'high', category: 'performance', title: 'Non-success HTTP status', description: `The final response returned HTTP ${response.status}.`, recommendation: 'Resolve the HTTP status before interpreting the rest of the audit.' }));
  if (categories.includes('seo')) findings.push(...seoFindings(document));
  if (categories.includes('performance')) findings.push(...performanceFindings(document, { responseMs, ttfbMs: responseMs }, htmlBytes, response.headers));
  if (categories.includes('security')) findings.push(...securityHeaderFindings(response.headers, new URL(response.url).protocol === 'https:'));
  if (categories.includes('accessibility')) findings.push(...accessibilityFindings(document));

  const filtered = findings.filter((finding) => categories.includes(finding.category));
  const summary = {
    errors: filtered.filter((f) => SEVERITY_ORDER.indexOf(f.severity) >= SEVERITY_ORDER.indexOf('high')).length,
    warnings: filtered.filter((f) => f.severity === 'medium' || f.severity === 'low').length,
    info: filtered.filter((f) => f.severity === 'info').length,
    byCategory: filtered.reduce<Record<string, number>>((acc, finding) => { acc[finding.category] = (acc[finding.category] || 0) + 1; return acc; }, {}),
  };

  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => { headers[k] = v; });

  return {
    url: url.toString(),
    finalUrl: response.url,
    status: response.status,
    fetchedAt: new Date().toISOString(),
    timing: { responseMs, ttfbMs: responseMs },
    document,
    headers,
    findings: filtered,
    summary,
  };
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(b) - SEVERITY_ORDER.indexOf(a);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
}

export function summarizeFindings(findings: Finding[]): { total: number; bySeverity: Partial<Record<Severity, number>>; byCategory: Partial<Record<FindingCategory, number>> } {
  const bySeverity: Partial<Record<Severity, number>> = {};
  const byCategory: Partial<Record<FindingCategory, number>> = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}

export function selectCategory(result: AuditResult, category: FindingCategory): AuditResult {
  const findings = result.findings.filter((finding) => finding.category === category);
  return {
    ...result,
    findings,
    summary: {
      ...result.summary,
      errors: findings.filter((finding) => SEVERITY_ORDER.indexOf(finding.severity) >= SEVERITY_ORDER.indexOf('high')).length,
      warnings: findings.filter((finding) => finding.severity === 'medium' || finding.severity === 'low').length,
      info: findings.filter((finding) => finding.severity === 'info').length,
    },
  };
}

export const __version = VERSION;
