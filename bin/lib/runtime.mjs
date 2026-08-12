// bin/lib/runtime.mjs
// Shared low-level runtime: SSRF defense, HTTP helpers, result helpers.
// Zero npm dependencies — this file is part of the portable plugin runtime.

import { lookup } from 'node:dns/promises';

export const VERSION = '0.3.0';
export const UA = `jedavid-web-tools/${VERSION} (+https://github.com/jesusdavidweb/jedavid-web-tools)`;

// Hard size cap for any fetched body (HTML, JSON, plain text). Defends against
// runaway responses and accidental downloads.
export const MAX_HTML = 2_500_000; // 2.5 MB
export const MAX_REDIRECTS = 5;
export const DEFAULT_TIMEOUT_MS = 15_000;

// Severity scale used across the toolkit. Lower index = lower severity.
export const SEVERITY = Object.freeze({
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
export function compareSeverity(a, b) {
  return SEVERITY_ORDER.indexOf(b) - SEVERITY_ORDER.indexOf(a);
}

export function hostnameUrl(input) {
  return /^https?:\/\//i.test(input) ? input : `https://${input}`;
}

export function trim(v) {
  return typeof v === 'string' ? v.trim() : '';
}

export function headersObj(h) {
  return Object.fromEntries([...h.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

// SSRF defense
// -------------

// Normalize a hostname before lookup/validation. This lowercases, strips a
// trailing dot and (best-effort) converts IDN to ASCII. Returns null when the
// input is not a usable hostname.
export function normalizeHostname(input) {
  if (typeof input !== 'string') return null;
  let host = input.trim().toLowerCase();
  if (!host) return null;
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host === '') return null;
  // Disallow obvious garbage / control characters.
  if (/[\s/?#]/.test(host)) return null;
  // Disallow raw IP literals that the URL parser will accept but that are not
  // meaningful in our use case.
  if (host === '0' || host === '0.0.0.0') return null;
  return host;
}

// IP family + private/special-use check.
//
// The list is intentionally conservative. We block all ranges that could be
// used to reach internal infrastructure, link-local services, cloud metadata
// endpoints or alternative routable addresses that resolve to internal space.
export function isPrivateIpv4(ip) {
  if (typeof ip !== 'string') return true;
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const o = parts.map((n) => {
    const v = Number(n);
    return Number.isInteger(v) && v >= 0 && v <= 255 ? v : null;
  });
  if (o.some((v) => v === null)) return true;
  const [a, b, c, d] = o;

  // RFC 1918, loopback, this-network, link-local, CGNAT, limited broadcast
  if (a === 0) return true;             // 0.0.0.0/8
  if (a === 10) return true;            // 10.0.0.0/8
  if (a === 127) return true;           // 127.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 IETF protocol
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && b === 18 && c < 2) return true;  // 198.18.0.0/15 benchmark
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 multicast
  if (a >= 240) return true;             // 240.0.0.0/4 reserved, 255.255.255.255 broadcast
  return false;
}

export function isPrivateIpv6(ip) {
  if (typeof ip !== 'string') return true;
  const lower = ip.toLowerCase().split('%')[0]; // strip zone id
  if (lower === '::' || lower === '::1') return true;
  if (lower === '::ffff:0:0' || lower === '64:ff9b::' || lower === '64:ff9b:1::') return true;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — re-check the embedded IPv4.
  const mapped = lower.match(/^::ffff:([0-9.]+)$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  // 6to4 — derive the embedded IPv4 from the first two 16-bit groups.
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
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 unique-local
  if (lower.startsWith('fe80:') || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true; // fe80::/10
  if (lower.startsWith('ff')) return true; // ff00::/8 multicast
  if (lower.startsWith('2001:db8')) return true; // 2001:db8::/32 documentation
  if (lower.startsWith('2001::') && lower.length <= 8) return true; // 2001::/32 Teredo
  return false;
}

export function isPrivateIp(ip) {
  if (typeof ip !== 'string' || !ip) return true;
  return ip.includes(':') ? isPrivateIpv6(ip) : isPrivateIpv4(ip);
}

// Asserts that a URL's scheme and resolved IP addresses are public. Caches
// per-host lookups within a single process to mitigate DNS rebinding races
// without preventing re-validation of the actual target IP at request time.
const _lookupCache = new Map(); // host -> [ip,ip,...] captured at first lookup
async function resolvePublic(host) {
  let addresses = _lookupCache.get(host);
  if (!addresses) {
    addresses = await lookup(host, { all: true });
    _lookupCache.set(host, addresses);
  }
  if (!addresses.length) return false;
  for (const a of addresses) {
    if (isPrivateIp(a.address)) return false;
  }
  return true;
}

export async function assertPublic(url) {
  if (!(url instanceof URL)) {
    throw new Error('Invalid URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP(S) URLs are supported.');
  }
  // Test escape hatch: only honored when the environment explicitly opts in.
  if (process.env.JEDAVID_TEST_ALLOW_LOOPBACK === '1') {
    if (url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === 'localhost') {
      return;
    }
  }
  const host = normalizeHostname(url.hostname);
  if (!host) throw new Error('Invalid hostname.');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('Localhost and local network hostnames are blocked.');
  }
  // If the hostname is a literal IP, validate it directly without DNS.
  if (/^[0-9.]+$/.test(host) || host.includes(':')) {
    if (isPrivateIp(host)) {
      throw new Error('Private/local network targets are blocked.');
    }
    return;
  }
  const ok = await resolvePublic(host);
  if (!ok) throw new Error('Private/local network targets are blocked.');
}

// HTTP helpers
// ------------

// safeFetch performs a manual redirect loop so that we can re-validate every
// hop against the SSRF policy. Returns the final response plus metadata.
export async function safeFetch(input, { method = 'GET', headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, maxRedirects = MAX_REDIRECTS, body, contentLength } = {}) {
  let url = new URL(hostnameUrl(input));
  for (let i = 0; i <= maxRedirects; i++) {
    await assertPublic(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = performance.now();
    let response;
    try {
      const opts = {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': UA, accept: '*/*', ...headers },
      };
      if (body !== undefined) opts.body = body;
      response = await fetch(url, opts);
    } finally {
      clearTimeout(timer);
    }
    const responseMs = Math.round(performance.now() - started);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const loc = response.headers.get('location');
      if (!loc) return { response, responseMs, url, redirected: i };
      if (i === maxRedirects) throw new Error('Too many redirects.');
      const next = new URL(loc, url);
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new Error('Redirect to a non-HTTP(S) target is blocked.');
      }
      url = next;
      continue;
    }
    return { response, responseMs, url, redirected: i };
  }
  throw new Error('Unable to fetch URL.');
}

export async function fetchText(input, options = {}) {
  const headers = { accept: 'text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.5', ...(options.headers || {}) };
  const result = await safeFetch(input, { ...options, headers });
  const text = await result.response.text();
  if (Buffer.byteLength(text) > MAX_HTML) {
    throw new Error(`Response exceeds ${MAX_HTML} bytes.`);
  }
  return { ...result, text };
}

export async function fetchJson(input, options = {}) {
  const headers = { accept: 'application/json', ...(options.headers || {}) };
  const result = await safeFetch(input, { ...options, headers });
  const body = await result.response.text();
  if (Buffer.byteLength(body) > MAX_HTML) {
    throw new Error(`Response exceeds ${MAX_HTML} bytes.`);
  }
  let data;
  try { data = JSON.parse(body); }
  catch { throw new Error(`Expected JSON from ${input}; HTTP ${result.response.status}.`); }
  if (!result.response.ok) {
    const snippet = typeof data === 'string' ? data : JSON.stringify(data).slice(0, 500);
    throw new Error(`HTTP ${result.response.status}: ${snippet}`);
  }
  return { ...result, data };
}

export async function fetchHead(input, options = {}) {
  return safeFetch(input, { ...options, method: 'HEAD' });
}

// Result helpers
// --------------

// Standardized tool result envelope. Every handler returns this shape so that
// agents can combine findings across tools predictably.
export function mkResult(tool, target, data, opts = {}) {
  return {
    ok: true,
    tool,
    target,
    summary: opts.summary || {},
    findings: opts.findings || [],
    evidence: opts.evidence || [],
    metadata: {
      fetchedAt: new Date().toISOString(),
      durationMs: opts.durationMs || 0,
      version: VERSION,
      ...(opts.metadata || {}),
    },
    data,
  };
}

export function mkFinding({ id, severity = SEVERITY.INFO, category, title, description, evidence, recommendation }) {
  return { id, severity, category, title, description, evidence, recommendation };
}

export function mkEvidence({ type, summary, data }) {
  return { type, summary, data };
}

export function addFinding(findings, finding) {
  findings.push(finding);
  return findings;
}

export function summarizeFindings(findings) {
  const by = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) by[f.severity] = (by[f.severity] || 0) + 1;
  return {
    total: findings.length,
    bySeverity: by,
    byCategory: findings.reduce((acc, f) => {
      acc[f.category] = (acc[f.category] || 0) + 1;
      return acc;
    }, {}),
  };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
}

export async function withTiming(fn) {
  const started = performance.now();
  const value = await fn();
  return { value, durationMs: Math.round(performance.now() - started) };
}

// Cloudflare helpers
// ------------------

export function bearerToken(envName) {
  const token = process.env[envName];
  if (!token) throw new Error(`${envName} is not configured in the MCP runtime environment.`);
  return { authorization: `Bearer ${token}` };
}

export async function cloudflareRequest(path, { account, token, method = 'GET', query, body } = {}) {
  const apiToken = token || process.env.CLOUDFLARE_API_TOKEN;
  if (!apiToken) throw new Error('CLOUDFLARE_API_TOKEN is not configured.');
  const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
  if (account || process.env.CLOUDFLARE_ACCOUNT_ID) {
    url.searchParams.set('account_id', account || process.env.CLOUDFLARE_ACCOUNT_ID);
  }
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
  }
  const headers = { authorization: `Bearer ${apiToken}`, accept: 'application/json' };
  const opts = { method, headers };
  if (body) { opts.body = JSON.stringify(body); opts.headers['content-type'] = 'application/json'; }
  const result = await safeFetch(url.toString(), { headers: opts.headers, method: opts.method, body: opts.body, timeoutMs: DEFAULT_TIMEOUT_MS });
  const text = await result.response.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`Cloudflare API returned non-JSON (HTTP ${result.response.status}).`); }
  if (!data.success) {
    const msg = (data.errors && data.errors[0] && data.errors[0].message) || 'Cloudflare API request failed.';
    const code = (data.errors && data.errors[0] && data.errors[0].code) || null;
    const err = new Error(`Cloudflare API: ${msg}`);
    err.code = code;
    throw err;
  }
  return data.result;
}

export function configuredBase(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not configured.`);
  const u = new URL(v);
  if (u.protocol !== 'https:') throw new Error(`${name} must use HTTPS.`);
  return u.origin;
}

export function wpAuthHeaders() {
  const u = process.env.WORDPRESS_USERNAME;
  const p = process.env.WORDPRESS_APP_PASSWORD;
  if (u && p) {
    return { authorization: `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}` };
  }
  return {};
}

export function wcAuthHeaders() {
  const k = process.env.WOOCOMMERCE_KEY;
  const s = process.env.WOOCOMMERCE_SECRET;
  if (!k || !s) throw new Error('WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET are not configured.');
  return { authorization: `Basic ${Buffer.from(`${k}:${s}`).toString('base64')}` };
}

export function githubHeaders(extra = {}) {
  const headers = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', ...extra };
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

// Coerce a Cloudflare error into a human-readable message including the most
// likely required permission scope when the API tells us.
export function describeCloudflareError(err) {
  const msg = err && err.message ? err.message : String(err);
  // Cloudflare permission error format variants:
  //   "Cloudflare API: Authentication error."
  //   "Cloudflare API: Missing required permission zone:read"
  //   "Cloudflare API: Missing permissions for zone X. Need permission Y: Z"
  const patterns = [
    /Missing required permission\s+([^\s.]+)/i,
    /Missing permissions? for\s+[^.]+?\.\s*([^.]+?)\.?\s*$/i,
    /Insufficient permissions[^\w]+([\w:]+)/i,
  ];
  for (const re of patterns) {
    const m = msg.match(re);
    if (m && m[1]) {
      return `${msg} (likely required scope: ${m[1].trim()})`;
    }
  }
  return msg;
}
