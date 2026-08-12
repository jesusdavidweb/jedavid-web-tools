// bin/lib/handlers.mjs
// Tool handlers. Each handler returns a standardized result envelope built
// with the helpers in runtime.mjs and html.mjs.
// Zero npm dependencies.

import {
  VERSION,
  UA,
  MAX_HTML,
  SEVERITY,
  safeFetch, fetchText, fetchJson, fetchHead,
  hostnameUrl, headersObj, trim,
  mkResult, mkFinding, mkEvidence, addFinding, summarizeFindings, sortFindings, withTiming,
  cloudflareRequest, configuredBase, wpAuthHeaders, wcAuthHeaders, githubHeaders,
  bearerToken, describeCloudflareError,
} from './runtime.mjs';
import {
  tagAttrs, tags, count, first,
  pageModel, extractJsonLdBlocks, flattenJsonLd, nodeType, nodeAllTypes,
  extractAnchors,
  seoFindings, performanceFindings, accessibilityFindings, securityHeaderFindings,
  securityCookieFindings, stackFindings, indexabilityFindings, llmFindings,
  schemaFindings, linkFindings,
} from './html.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function isHttps(url) {
  return typeof url === 'string' && url.toLowerCase().startsWith('https://');
}

function ok(tool, target, data, opts = {}) {
  return mkResult(tool, target, data, opts);
}

function err(tool, target, message) {
  return { ok: false, tool, target, error: { message } };
}

// Audit a single page. This is the workhorse that combines every category.
async function auditPage(input, { tool = 'site_audit' } = {}) {
  const { value: fetched, durationMs } = await withTiming(() => fetchText(input));
  const model = pageModel(fetched.text, fetched.url);
  const htmlBytes = Buffer.byteLength(fetched.text);
  const isHttpsFinal = isHttps(fetched.url.toString());

  const findings = [
    ...seoFindings(model),
    ...performanceFindings(model, { responseMs: fetched.responseMs, htmlBytes, headers: fetched.response.headers }),
    ...accessibilityFindings(model),
    ...securityHeaderFindings(fetched.response.headers, isHttpsFinal),
    ...linkFindings(extractAnchors(fetched.text, fetched.url)),
  ];

  // Cookies
  const setCookies = fetched.response.headers.getSetCookie ? fetched.response.headers.getSetCookie() : [];
  if (setCookies.length > 0) {
    const cookieFindings = securityCookieFindings(setCookies.map((raw) => parseSetCookie(raw))).map((f) => ({ ...f, evidence: { cookie: f.evidence } }));
    findings.push(...cookieFindings);
  }

  const stack = stackFindings(fetched.text, fetched.response.headers);

  // Stack-detect findings
  for (const t of stack) {
    findings.push(mkFinding({ id: `stack.${slug(t.name)}`, severity: SEVERITY.INFO, category: 'stack', title: `Detected: ${t.name}`, description: t.evidence, evidence: { confidence: t.confidence } }));
  }

  const data = {
    request: { url: hostnameUrl(input), method: 'GET' },
    response: {
      status: fetched.response.status,
      finalUrl: fetched.url.toString(),
      responseMs: fetched.responseMs,
      redirected: fetched.redirected,
      httpVersion: fetched.response.httpVersion || null,
      headers: headersObj(fetched.response.headers),
      cookies: setCookies,
    },
    document: {
      htmlBytes,
      contentType: fetched.response.headers.get('content-type'),
      contentEncoding: fetched.response.headers.get('content-encoding'),
      cacheControl: fetched.response.headers.get('cache-control'),
      title: model.title,
      description: model.description,
      canonical: model.canonical,
      lang: model.lang,
      viewport: model.viewport,
      robots: model.robots,
      headings: model.headings,
      images: { total: model.imageCount, missingAlt: model.imagesMissingAlt, missingDimensions: model.imagesMissingDimensions, lazy: model.imagesLazy },
      scripts: { external: model.scriptExternal, inline: model.scriptInline, renderBlocking: model.scriptRenderBlocking },
      stylesheets: model.stylesheetCount,
      hreflangs: model.hreflangs,
      pagination: model.pagination,
      preload: model.preload,
      preconnect: model.preconnect,
      modulepreload: model.modulepreload,
      dnsPrefetch: model.dnsPrefetch,
      og: model.og,
      twitter: model.twitter,
      structured: { jsonLd: model.jsonLdCount, microdata: model.microdataCount, rdfa: model.rdfaCount },
      landmarks: model.landmarks,
      iframes: { total: model.iframeCount, missingTitle: model.iframesMissingTitle },
      forms: { forms: model.forms, inputs: model.inputs, labels: model.labels, buttons: model.buttons },
    },
    stack,
  };

  const summary = summarizeFindings(findings);
  return ok(tool, hostnameUrl(input), data, {
    findings: sortFindings(findings),
    summary,
    durationMs,
    evidence: [
      mkEvidence({ type: 'http', summary: `HTTP ${fetched.response.status} in ${fetched.responseMs} ms`, data: { headers: data.response.headers, responseMs: fetched.responseMs } }),
      mkEvidence({ type: 'html', summary: `${(htmlBytes / 1024).toFixed(1)} KiB HTML`, data: { htmlBytes, model } }),
    ],
    metadata: { isHttps: isHttpsFinal, redirected: fetched.redirected > 0 },
  });
}

function parseSetCookie(raw) {
  if (!raw) return { name: null, secure: false, httpOnly: false, sameSite: null, path: null, raw };
  const parts = raw.split(';').map((p) => p.trim());
  const [first] = parts;
  const eq = first.indexOf('=');
  const name = eq >= 0 ? first.slice(0, eq).trim() : first;
  return {
    name,
    secure: /;\s*secure\b/i.test(raw),
    httpOnly: /;\s*httponly\b/i.test(raw),
    sameSite: (raw.match(/;\s*samesite=([^;]+)/i) || [])[1] || null,
    path: (raw.match(/;\s*path=([^;]+)/i) || [])[1] || null,
    domain: (raw.match(/;\s*domain=([^;]+)/i) || [])[1] || null,
    expires: (raw.match(/;\s*expires=([^;]+)/i) || [])[1] || null,
    raw,
  };
}

function slug(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

// Tool handlers
// -------------

const handlers = {
  // -- Web / audit -----------------------------------------------------------

  async site_audit({ url }) {
    return auditPage(url, { tool: 'site_audit' });
  },

  async http_inspect({ url }) {
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const setCookies = fetched.response.headers.getSetCookie ? fetched.response.headers.getSetCookie() : [];
    const data = {
      finalUrl: fetched.url.toString(),
      status: fetched.response.status,
      ok: fetched.response.ok,
      responseMs: fetched.responseMs,
      redirected: fetched.redirected,
      httpVersion: fetched.response.httpVersion || null,
      contentType: fetched.response.headers.get('content-type'),
      contentLength: Number(fetched.response.headers.get('content-length')) || null,
      contentEncoding: fetched.response.headers.get('content-encoding'),
      cacheControl: fetched.response.headers.get('cache-control'),
      headers: headersObj(fetched.response.headers),
      cookies: setCookies.map(parseSetCookie),
    };
    const findings = [];
    if (!fetched.response.ok) {
      findings.push(mkFinding({ id: 'http.status', severity: SEVERITY.HIGH, category: 'http', title: `Non-success status ${fetched.response.status}`, description: `The response returned HTTP ${fetched.response.status}.`, recommendation: 'Investigate the upstream error.' }));
    }
    if (fetched.redirected > 3) {
      findings.push(mkFinding({ id: 'http.redirect.many', severity: SEVERITY.LOW, category: 'http', title: 'Many redirects', description: `${fetched.redirected} redirects were followed.`, recommendation: 'Tighten redirect chains where possible.' }));
    }
    return ok('http_inspect', hostnameUrl(url), data, { findings, summary: summarizeFindings(findings), durationMs, evidence: [mkEvidence({ type: 'http', summary: `HTTP ${fetched.response.status} in ${fetched.responseMs} ms`, data: { headers: data.headers } })] });
  },

  async performance_audit({ url }) {
    const result = await auditPage(url, { tool: 'performance_audit' });
    result.findings = result.findings.filter((f) => f.category === 'performance');
    result.summary = summarizeFindings(result.findings);
    return result;
  },

  async performance_assets({ url, limit = 25 }) {
    const cap = Math.min(Math.max(Number(limit) || 25, 1), 50);
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const base = fetched.url;
    const refs = [];
    for (const s of tags(fetched.text, 'script')) if (s.attrs.src) refs.push(['script', s.attrs.src]);
    for (const l of tags(fetched.text, 'link')) {
      const rel = (l.attrs.rel || '').toLowerCase();
      if (rel === 'stylesheet' && l.attrs.href) refs.push(['stylesheet', l.attrs.href]);
      if (rel === 'modulepreload' && l.attrs.href) refs.push(['modulepreload', l.attrs.href]);
      if (rel === 'preload' && l.attrs.href) refs.push(['preload', l.attrs.href]);
    }
    for (const i of tags(fetched.text, 'img')) if (i.attrs.src) refs.push(['image', i.attrs.src]);
    for (const m of tags(fetched.text, 'meta')) if (i_tagSrc(m)) refs.push(['resource', i_tagSrc(m)]);
    function i_tagSrc(m) { /* placeholder: never called; reserved for future extensions */ return null; }
    const unique = [];
    const seen = new Set();
    for (const [type, raw] of refs) {
      let abs;
      try { abs = new URL(raw, base); } catch { continue; }
      if (abs.origin !== base.origin) continue; // only same-origin in v1
      if (seen.has(abs.href)) continue;
      seen.add(abs.href);
      unique.push({ type, url: abs.href });
      if (unique.length >= cap) break;
    }
    const results = [];
    for (const r of unique) {
      try {
        const y = await safeFetch(r.url, { method: 'HEAD', timeoutMs: 7_000 });
        const headers = y.response.headers;
        const bytes = Number(headers.get('content-length')) || null;
        results.push({
          type: r.type,
          url: r.url,
          status: y.response.status,
          contentType: headers.get('content-type'),
          contentLength: bytes,
          contentEncoding: headers.get('content-encoding'),
          cacheControl: headers.get('cache-control'),
          responseMs: y.responseMs,
          estimatedKiB: bytes ? +(bytes / 1024).toFixed(1) : null,
        });
      } catch (e) {
        results.push({ type: r.type, url: r.url, error: e.message });
      }
    }
    const findings = [];
    const totalBytes = results.reduce((a, r) => a + (r.contentLength || 0), 0);
    if (totalBytes > 1_500_000) {
      findings.push(mkFinding({ id: 'perf.assets.total_heavy', severity: SEVERITY.MEDIUM, category: 'performance', title: 'Total same-origin weight is heavy', description: `Same-origin assets total ${(totalBytes / 1024 / 1024).toFixed(2)} MiB.`, recommendation: 'Audit large assets, enable compression, split bundles and serve modern formats.' }));
    }
    for (const r of results) {
      if (r.contentLength && r.contentLength > 250_000) {
        findings.push(mkFinding({ id: `perf.assets.large.${slug(r.url)}`, severity: SEVERITY.MEDIUM, category: 'performance', title: `Large ${r.type} asset`, description: `${r.url} is ${(r.contentLength / 1024).toFixed(1)} KiB.`, recommendation: 'Consider code-splitting, image optimization or font subsetting.' }));
      }
      if (r.cacheControl === null) {
        findings.push(mkFinding({ id: `perf.assets.cache.${slug(r.url)}`, severity: SEVERITY.LOW, category: 'performance', title: `No Cache-Control on ${r.type}`, description: `${r.url} has no Cache-Control header.`, recommendation: 'Add a long-lived Cache-Control for fingerprinted assets.' }));
      }
    }
    return ok('performance_assets', hostnameUrl(url), { page: base.toString(), count: results.length, totalBytes, resources: results }, {
      findings, summary: summarizeFindings(findings), durationMs,
      evidence: [mkEvidence({ type: 'asset', summary: `${results.length} same-origin assets, ${(totalBytes / 1024).toFixed(1)} KiB total`, data: { results } })],
    });
  },

  async seo_audit({ url }) {
    const result = await auditPage(url, { tool: 'seo_audit' });
    result.findings = result.findings.filter((f) => f.category === 'seo' || f.category === 'llm' || f.id.startsWith('schema.') || f.id.startsWith('links.'));
    result.summary = summarizeFindings(result.findings);
    return result;
  },

  async seo_indexability({ url }) {
    const page = await auditPage(url, { tool: 'seo_indexability' });
    const robots = await handlers.robots_inspect({ url }).catch((e) => ({ error: e.message }));
    const xRobotsTag = page.data.response.headers['x-robots-tag'] || null;
    const findings = indexabilityFindings({
      status: page.data.response.status,
      robotsMeta: page.data.document.robots,
      xRobotsTag,
      canonical: page.data.document.canonical,
      robotsTxt: robots && !robots.error ? robots.data : null,
      finalUrl: page.data.response.finalUrl,
    });
    return ok('seo_indexability', hostnameUrl(url), {
      finalUrl: page.data.response.finalUrl,
      status: page.data.response.status,
      robotsMeta: page.data.document.robots,
      xRobotsTag,
      canonical: page.data.document.canonical,
      lang: page.data.document.lang,
      hreflangs: page.data.document.hreflangs,
      indexable: page.data.response.status >= 200 && page.data.response.status < 300 && !/\bnoindex\b/i.test(page.data.document.robots || '') && !/\bnoindex\b/i.test(xRobotsTag || ''),
      robotsTxt: robots && !robots.error ? robots.data : (robots || null),
    }, { findings, summary: summarizeFindings(findings), durationMs: page.metadata.durationMs });
  },

  async seo_links({ url }) {
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const base = fetched.url;
    const anchors = extractAnchors(fetched.text, base);
    const internal = anchors.filter((a) => a.internal === true);
    const external = anchors.filter((a) => a.internal === false);
    const nofollow = anchors.filter((a) => a.nofollow);
    const emptyText = anchors.filter((a) => !a.text);
    const findings = linkFindings(anchors);
    return ok('seo_links', hostnameUrl(url), {
      page: base.toString(),
      total: anchors.length,
      internal: internal.length,
      external: external.length,
      nofollow: nofollow.length,
      emptyText: emptyText.length,
      sample: {
        internal: internal.slice(0, 50).map((a) => ({ href: a.absolute, text: a.text })),
        external: external.slice(0, 50).map((a) => ({ href: a.absolute, text: a.text, nofollow: a.nofollow })),
      },
    }, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async seo_schema({ url }) {
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const blocks = extractJsonLdBlocks(fetched.text);
    const parsed = blocks.map((b) => {
      if (!b.valid) return { valid: false, error: b.error, raw: b.raw.slice(0, 1000) };
      const nodes = flattenJsonLd(b.data).map((n) => ({ type: nodeType(n), allTypes: nodeAllTypes(n), id: n['@id'] || null, keys: Object.keys(n) }));
      return { valid: true, types: [...new Set(nodes.flatMap((n) => n.allTypes))], nodes };
    });
    const types = [...new Set(parsed.filter((p) => p.valid).flatMap((p) => p.types))];
    const findings = schemaFindings(blocks);
    return ok('seo_schema', hostnameUrl(url), {
      url: fetched.url.toString(),
      blocksTotal: blocks.length,
      blocksValid: parsed.filter((p) => p.valid).length,
      blocksInvalid: parsed.filter((p) => !p.valid).length,
      types,
      blocks: parsed,
    }, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async seo_llm({ url }) {
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const origin = fetched.url.origin;
    let llmsTxt = null;
    try {
      const llms = await fetchText(`${origin}/llms.txt`, { timeoutMs: 7_000 });
      llmsTxt = { present: llms.response.ok, status: llms.response.status, url: llms.url.toString(), size: Buffer.byteLength(llms.text), preview: llms.response.ok ? llms.text.slice(0, 4000) : null };
    } catch (e) {
      llmsTxt = { present: false, status: null, error: e.message };
    }
    let robotsTxt = null;
    try {
      const rt = await handlers.robots_inspect({ url });
      robotsTxt = rt.data;
    } catch (e) { robotsTxt = { error: e.message }; }
    const blocks = extractJsonLdBlocks(fetched.text);
    const model = pageModel(fetched.text, fetched.url);
    const findings = llmFindings({ llmsTxt, robotsTxt, jsonLd: blocks, model });
    const aiBots = ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Google-Extended', 'PerplexityBot', 'Applebot-Extended', 'Bytespider', 'CCBot'];
    const aiCrawlerMentions = Object.fromEntries(aiBots.map((b) => {
      const inUa = robotsTxt && robotsTxt.userAgents && robotsTxt.userAgents.some((u) => u.toLowerCase() === b.toLowerCase());
      return [b, inUa];
    }));
    return ok('seo_llm', hostnameUrl(url), {
      url: fetched.url.toString(),
      llmsTxt,
      robotsTxt,
      aiCrawlerMentions,
      semantic: { lang: model.lang, title: model.title, description: model.description, canonical: model.canonical, og: model.og, twitter: model.twitter },
      structuredData: { jsonLd: blocks.length, types: [...new Set(blocks.filter((b) => b.valid).flatMap((b) => flattenJsonLd(b.data)).map(nodeType).filter(Boolean))] },
    }, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async accessibility_audit({ url }) {
    const result = await auditPage(url, { tool: 'accessibility_audit' });
    result.findings = result.findings.filter((f) => f.category === 'accessibility');
    result.summary = summarizeFindings(result.findings);
    return result;
  },

  async security_headers({ url }) {
    const result = await auditPage(url, { tool: 'security_headers' });
    result.findings = result.findings.filter((f) => f.category === 'security' && !f.id.startsWith('security.cookies'));
    result.summary = summarizeFindings(result.findings);
    return result;
  },

  async security_cookies({ url }) {
    const { value: fetched, durationMs } = await withTiming(() => fetchText(url));
    const raw = fetched.response.headers.getSetCookie ? fetched.response.headers.getSetCookie() : [];
    const cookies = raw.map(parseSetCookie);
    const findings = securityCookieFindings(cookies);
    return ok('security_cookies', hostnameUrl(url), {
      url: fetched.url.toString(),
      isHttps: isHttps(fetched.url.toString()),
      count: cookies.length,
      cookies,
    }, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async stack_detect({ url }) {
    const result = await auditPage(url, { tool: 'stack_detect' });
    return ok('stack_detect', hostnameUrl(url), {
      url: result.data.response.finalUrl,
      technologies: result.data.stack,
      server: result.data.response.headers.server || null,
      poweredBy: result.data.response.headers['x-powered-by'] || null,
      cfRay: result.data.response.headers['cf-ray'] || null,
      vercelId: result.data.response.headers['x-vercel-id'] || null,
      netlify: result.data.response.headers['x-nf-request-id'] || null,
    }, { findings: result.findings.filter((f) => f.category === 'stack'), summary: summarizeFindings(result.findings.filter((f) => f.category === 'stack')), durationMs: result.metadata.durationMs });
  },

  async robots_inspect({ url }) {
    const origin = new URL(hostnameUrl(url)).origin;
    let fetched; let durationMs; let error;
    try { ({ value: fetched, durationMs } = await withTiming(() => fetchText(`${origin}/robots.txt`, { timeoutMs: 7_000 }))); } catch (e) { error = e.message; }
    const data = error
      ? { status: null, present: false, error, sitemaps: [], userAgents: [], disallow: [], allow: [], raw: null }
      : (() => {
          const lines = fetched.text.split(/\r?\n/).map((s) => s.trim());
          const sitemaps = lines.filter((l) => /^sitemap:/i.test(l)).map((l) => l.replace(/^sitemap:\s*/i, ''));
          const userAgents = lines.filter((l) => /^user-agent:/i.test(l)).map((l) => l.replace(/^user-agent:\s*/i, ''));
          const disallow = lines.filter((l) => /^disallow:/i.test(l)).map((l) => l.replace(/^disallow:\s*/i, ''));
          const allow = lines.filter((l) => /^allow:/i.test(l)).map((l) => l.replace(/^allow:\s*/i, ''));
          return { status: fetched.response.status, present: fetched.response.ok, url: fetched.url.toString(), sitemaps, userAgents, disallow, allow, raw: fetched.text.slice(0, 8000) };
        })();
    const findings = [];
    if (!data.present) {
      findings.push(mkFinding({ id: 'robots.missing', severity: SEVERITY.LOW, category: 'crawlability', title: 'robots.txt not present', description: 'No robots.txt was returned.', recommendation: 'Publish a robots.txt, even if minimal.' }));
    }
    if (data.sitemaps.length === 0) {
      findings.push(mkFinding({ id: 'robots.sitemap_undeclared', severity: SEVERITY.INFO, category: 'crawlability', title: 'robots.txt does not declare a sitemap', description: 'No Sitemap directive was found.', recommendation: 'Declare your sitemap(s) in robots.txt.' }));
    }
    return ok('robots_inspect', hostnameUrl(url), data, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async sitemap_inspect({ url, limit = 100 }) {
    const cap = Math.min(Math.max(Number(limit) || 100, 1), 500);
    const origin = new URL(hostnameUrl(url)).origin;
    let fetched; let durationMs; let error;
    try { ({ value: fetched, durationMs } = await withTiming(() => fetchText(`${origin}/sitemap.xml`, { timeoutMs: 7_000 }))); } catch (e) { error = e.message; }
    if (error) {
      return ok('sitemap_inspect', hostnameUrl(url), { present: false, error }, { findings: [mkFinding({ id: 'sitemap.missing', severity: SEVERITY.INFO, category: 'crawlability', title: 'Sitemap not reachable', description: error, recommendation: 'Verify that /sitemap.xml is published and reachable.' })], summary: { total: 0, bySeverity: {}, byCategory: {} }, durationMs });
    }
    const text = fetched.text;
    const type = /<sitemapindex\b/i.test(text) ? 'index' : /<urlset\b/i.test(text) ? 'urlset' : 'unknown';
    const entries = [...text.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi)].map((m) => m[1].trim());
    const lastmod = [...text.matchAll(/<lastmod>\s*([^<]+)\s*<\/lastmod>/gi)].map((m) => m[1].trim());
    const findings = [];
    if (!fetched.response.ok) {
      findings.push(mkFinding({ id: 'sitemap.status', severity: SEVERITY.MEDIUM, category: 'crawlability', title: `Sitemap returned HTTP ${fetched.response.status}`, description: `Final status ${fetched.response.status}.`, recommendation: 'Ensure /sitemap.xml returns 200.' }));
    }
    if (entries.length === 0) {
      findings.push(mkFinding({ id: 'sitemap.empty', severity: SEVERITY.INFO, category: 'crawlability', title: 'Sitemap is empty', description: 'No <loc> entries were parsed.', recommendation: 'Populate the sitemap with the URLs you want crawled.' }));
    }
    return ok('sitemap_inspect', hostnameUrl(url), {
      url: fetched.url.toString(),
      present: fetched.response.ok,
      type,
      total: entries.length,
      lastmodCount: lastmod.length,
      entries: entries.slice(0, cap),
    }, { findings, summary: summarizeFindings(findings), durationMs });
  },

  async page_compare({ before, after }) {
    const [a, b] = await Promise.all([auditPage(before, { tool: 'page_compare.before' }), auditPage(after, { tool: 'page_compare.after' })]);
    const diff = (k) => ({ before: a.data[k], after: b.data[k], delta: typeof a.data[k] === 'number' && typeof b.data[k] === 'number' ? a.data[k] - b.data[k] : null });
    const docMetric = (k) => ({ before: a.data.document[k], after: b.data.document[k] });
    return ok('page_compare', `${before} <> ${after}`, {
      before: a.data.response.finalUrl,
      after: b.data.response.finalUrl,
      status: { before: a.data.response.status, after: b.data.response.status },
      responseMs: { before: a.data.response.responseMs, after: b.data.response.responseMs, delta: a.data.response.responseMs - b.data.response.responseMs },
      htmlBytes: { before: Buffer.byteLength('x'), after: Buffer.byteLength('x'), delta: null },
      findings: { before: a.findings.length, after: b.findings.length, delta: b.findings.length - a.findings.length },
      scripts: docMetric('scripts'),
      images: docMetric('images'),
    }, {
      findings: [...a.findings, ...b.findings].sort((x, y) => (y.severity === x.severity ? 0 : 0)),
      summary: summarizeFindings([...a.findings, ...b.findings]),
      durationMs: Math.max(a.metadata.durationMs, b.metadata.durationMs),
    });
  },

  async redirect_trace({ url, max = 10 }) {
    const cap = Math.min(Math.max(Number(max) || 10, 1), 20);
    const hops = [];
    let current = new URL(hostnameUrl(url));
    for (let i = 0; i <= cap; i++) {
      await (await import('./runtime.mjs')).assertPublic(current);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 7_000);
      let response;
      try {
        response = await fetch(current, { method: 'GET', redirect: 'manual', signal: controller.signal, headers: { 'user-agent': UA, accept: '*/*' } });
      } finally { clearTimeout(timer); }
      hops.push({ index: i, url: current.toString(), status: response.status, location: response.headers.get('location') || null, headers: Object.fromEntries([...response.headers.entries()].filter(([k]) => ['server', 'location', 'cf-ray', 'x-cache', 'x-vercel-id'].includes(k.toLowerCase()))) });
      if (![301, 302, 303, 307, 308].includes(response.status) || !response.headers.get('location')) break;
      const next = new URL(response.headers.get('location'), current);
      if (next.protocol !== 'http:' && next.protocol !== 'https:') break;
      if (next.toString() === current.toString()) break;
      current = next;
      if (i === cap) hops[hops.length - 1].truncated = true;
    }
    const findings = [];
    if (hops.length > 4) findings.push(mkFinding({ id: 'redirect.long', severity: SEVERITY.LOW, category: 'http', title: 'Long redirect chain', description: `${hops.length} hops.`, recommendation: 'Tighten redirect chains.' }));
    const seen = new Set();
    for (const h of hops) {
      if (seen.has(h.url)) {
        findings.push(mkFinding({ id: 'redirect.loop', severity: SEVERITY.HIGH, category: 'http', title: 'Redirect loop detected', description: `URL ${h.url} appears more than once in the chain.`, recommendation: 'Fix the redirect loop.' }));
        break;
      }
      seen.add(h.url);
    }
    const finalHop = hops[hops.length - 1];
    const finalProtocol = new URL(finalHop.url).protocol;
    const initialProtocol = new URL(hops[0].url).protocol;
    if (initialProtocol === 'http:' && finalProtocol === 'https:') {
      findings.push(mkFinding({ id: 'redirect.http_to_https', severity: SEVERITY.INFO, category: 'http', title: 'HTTP upgraded to HTTPS', description: `Redirect chain starts with HTTP and ends with HTTPS.`, recommendation: 'This is a positive signal; ensure HSTS is enabled.' }));
    }
    return ok('redirect_trace', hostnameUrl(url), { hops, final: finalHop }, { findings, summary: summarizeFindings(findings) });
  },

  // -- Cloudflare -----------------------------------------------------------

  async cloudflare_account() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}`);
      return ok('cloudflare_account', `account:${account}`, { id: data.id, name: data.name, type: data.type, createdOn: data.created_on });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_zones() {
    try {
      const data = await cloudflareRequest('/zones', { query: { per_page: 50 } });
      return ok('cloudflare_zones', 'account', { count: data.length, zones: data.map((z) => ({ id: z.id, name: z.name, status: z.status, paused: z.paused, type: z.type, plan: z.plan?.name || null, nameServers: z.name_servers })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_zone({ domain }) {
    try {
      const data = await cloudflareRequest('/zones', { query: { name: domain } });
      if (!data.length) throw new Error(`No Cloudflare zone found for ${domain}.`);
      const z = data[0];
      return ok('cloudflare_zone', domain, { id: z.id, name: z.name, status: z.status, paused: z.paused, type: z.type, nameServers: z.name_servers, plan: z.plan?.name || null, createdOn: z.created_on, modifiedOn: z.modified_on });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_dns({ domain, type }) {
    try {
      const data = await cloudflareRequest('/zones', { query: { name: domain } });
      if (!data.length) throw new Error(`No Cloudflare zone found for ${domain}.`);
      const z = data[0];
      const records = await cloudflareRequest(`/zones/${z.id}/dns_records`, { query: { per_page: 100, type } });
      return ok('cloudflare_dns', domain, { zone: { id: z.id, name: z.name }, count: records.length, records: records.map((r) => ({ id: r.id, type: r.type, name: r.name, content: r.content, proxied: r.proxied, ttl: r.ttl, priority: r.priority || null })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_workers() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/workers/scripts`, { query: { per_page: 100 } });
      return ok('cloudflare_workers', `account:${account}`, { count: (data || []).length, scripts: (data || []).map((s) => ({ id: s.id, createdOn: s.created_on, modifiedOn: s.modified_on, etag: s.etag })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_pages() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/pages/projects`, { query: { per_page: 100 } });
      return ok('cloudflare_pages', `account:${account}`, { count: (data || []).length, projects: (data || []).map((p) => ({ name: p.name, id: p.id, subdomain: p.subdomain, createdOn: p.created_on, productionBranch: p.production_branch })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_d1() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/d1/database`, { query: { per_page: 100 } });
      return ok('cloudflare_d1', `account:${account}`, { count: (data || []).length, databases: (data || []).map((d) => ({ uuid: d.uuid, name: d.name, version: d.version, createdAt: d.created_at, fileSize: d.file_size, numTables: d.num_tables })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_r2() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/r2/buckets`, { query: { per_page: 100 } });
      return ok('cloudflare_r2', `account:${account}`, { count: (data || []).length, buckets: (data || []).map((b) => ({ name: b.name, creationDate: b.creation_date, location: b.location })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_kv() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/storage/kv/namespaces`, { query: { per_page: 100 } });
      return ok('cloudflare_kv', `account:${account}`, { count: (data || []).length, namespaces: (data || []).map((n) => ({ id: n.id, title: n.title, supportsUrlEncoding: n.supports_url_encoding })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_queues() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/queues`, { query: { per_page: 100 } });
      return ok('cloudflare_queues', `account:${account}`, { count: (data || []).length, queues: (data || []).map((q) => ({ id: q.id, name: q.name, createdOn: q.created_on, modifiedOn: q.modified_on, producersTotal: q.producers_total, consumersTotal: q.consumers_total })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  async cloudflare_access() {
    try {
      const account = process.env.CLOUDFLARE_ACCOUNT_ID;
      if (!account) throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.');
      const data = await cloudflareRequest(`/accounts/${encodeURIComponent(account)}/access/apps`, { query: { per_page: 100 } });
      return ok('cloudflare_access', `account:${account}`, { count: (data || []).length, apps: (data || []).map((a) => ({ id: a.id, name: a.name, type: a.type, domain: a.domain, sessionDuration: a.session_duration, createdAt: a.created_at, updatedAt: a.updated_at })) });
    } catch (e) { throw new Error(describeCloudflareError(e)); }
  },

  // -- GitHub ---------------------------------------------------------------

  async github_repo({ repo }) {
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}`, { headers: githubHeaders() }));
    return ok('github_repo', repo, {
      fullName: data.full_name,
      private: data.private,
      defaultBranch: data.default_branch,
      language: data.language,
      archived: data.archived,
      disabled: data.disabled,
      visibility: data.visibility,
      openIssues: data.open_issues_count,
      forks: data.forks_count,
      stargazers: data.stargazers_count,
      pushedAt: data.pushed_at,
      updatedAt: data.updated_at,
      createdAt: data.created_at,
      license: data.license?.spdx_id || null,
      topics: data.topics || [],
      description: data.description,
      homepage: data.homepage,
    }, { durationMs });
  },

  async github_branches({ repo, limit = 30 }) {
    const cap = Math.min(Math.max(Number(limit) || 30, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/branches?per_page=${cap}`, { headers: githubHeaders() }));
    return ok('github_branches', repo, { count: data.length, branches: data.map((b) => ({ name: b.name, protected: b.protected, sha: b.commit?.sha })) }, { durationMs });
  },

  async github_pull_requests({ repo, state = 'open', limit = 20 }) {
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/pulls?state=${encodeURIComponent(state)}&per_page=${cap}`, { headers: githubHeaders() }));
    return ok('github_pull_requests', repo, { count: data.length, state, pullRequests: data.map((p) => ({ number: p.number, title: p.title, state: p.state, draft: p.draft, user: p.user?.login, base: p.base?.ref, head: p.head?.ref, createdAt: p.created_at, updatedAt: p.updated_at, url: p.html_url })) }, { durationMs });
  },

  async github_issues({ repo, state = 'open', limit = 20 }) {
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/issues?state=${encodeURIComponent(state)}&per_page=${cap}`, { headers: githubHeaders() }));
    const issues = data.filter((i) => !i.pull_request);
    return ok('github_issues', repo, { count: issues.length, state, issues: issues.map((i) => ({ number: i.number, title: i.title, state: i.state, user: i.user?.login, labels: (i.labels || []).map((l) => l.name), createdAt: i.created_at, updatedAt: i.updated_at, url: i.html_url })) }, { durationMs });
  },

  async github_releases({ repo, limit = 10 }) {
    const cap = Math.min(Math.max(Number(limit) || 10, 1), 50);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/releases?per_page=${cap}`, { headers: githubHeaders() }));
    return ok('github_releases', repo, { count: data.length, releases: data.map((r) => ({ id: r.id, name: r.name || r.tag_name, tag: r.tag_name, draft: r.draft, prerelease: r.prerelease, publishedAt: r.published_at, url: r.html_url })) }, { durationMs });
  },

  async github_actions({ repo, limit = 10 }) {
    const cap = Math.min(Math.max(Number(limit) || 10, 1), 30);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/actions/runs?per_page=${cap}`, { headers: githubHeaders() }));
    return ok('github_actions', repo, { count: (data.workflow_runs || []).length, runs: (data.workflow_runs || []).map((r) => ({ id: r.id, name: r.name, event: r.event, status: r.status, conclusion: r.conclusion, branch: r.head_branch, sha: r.head_sha, createdAt: r.created_at, updatedAt: r.updated_at, url: r.html_url })) }, { durationMs });
  },

  async github_workflow_runs({ repo, workflow, limit = 20 }) {
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 50);
    const path = workflow ? `/repos/${repo}/actions/workflows/${encodeURIComponent(workflow)}/runs?per_page=${cap}` : `/repos/${repo}/actions/runs?per_page=${cap}`;
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com${path}`, { headers: githubHeaders() }));
    return ok('github_workflow_runs', repo, { count: (data.workflow_runs || []).length, runs: (data.workflow_runs || []).map((r) => ({ id: r.id, name: r.name, status: r.status, conclusion: r.conclusion, branch: r.head_branch, sha: r.head_sha, runNumber: r.run_number, url: r.html_url })) }, { durationMs });
  },

  async github_deployments({ repo, limit = 20 }) {
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`https://api.github.com/repos/${repo}/deployments?per_page=${cap}`, { headers: githubHeaders() }));
    return ok('github_deployments', repo, { count: data.length, deployments: data.map((d) => ({ id: d.id, environment: d.environment, ref: d.ref, sha: d.sha, createdAt: d.created_at, url: d.url })) }, { durationMs });
  },

  // -- WordPress ------------------------------------------------------------

  async wordpress_rest_index() {
    const base = configuredBase('WORDPRESS_BASE_URL');
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/`, { headers: wpAuthHeaders() }));
    return ok('wordpress_rest_index', base, { name: data.name, description: data.description, url: data.url, home: data.home, namespaces: data.namespaces, routes: Object.keys(data.routes || {}).slice(0, 500) }, { durationMs });
  },

  async wordpress_plugins() {
    const base = configuredBase('WORDPRESS_BASE_URL');
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wp/v2/plugins?per_page=100`, { headers: wpAuthHeaders() }));
    return ok('wordpress_plugins', base, { count: data.length, plugins: data.map((p) => ({ plugin: p.plugin, status: p.status, name: p.name?.rendered || p.name, version: p.version, author: p.author, networkOnly: p.network_only, updateAvailable: p.update?.available || null })) }, { durationMs });
  },

  async wordpress_themes() {
    const base = configuredBase('WORDPRESS_BASE_URL');
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wp/v2/themes?per_page=100`, { headers: wpAuthHeaders() }));
    return ok('wordpress_themes', base, { count: data.length, themes: data.map((t) => ({ stylesheet: t.stylesheet, name: t.name?.rendered || t.name, status: t.status, version: t.version, author: t.author, updateAvailable: t.update?.available || null })) }, { durationMs });
  },

  async wordpress_users({ limit = 20 }) {
    const base = configuredBase('WORDPRESS_BASE_URL');
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wp/v2/users?per_page=${cap}&context=edit`, { headers: wpAuthHeaders() }));
    return ok('wordpress_users', base, { count: data.length, users: data.map((u) => ({ id: u.id, name: u.name, slug: u.slug, roles: u.roles, registered: u.registered_date })) }, { durationMs });
  },

  // -- WooCommerce ----------------------------------------------------------

  async woocommerce_system_status() {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/system_status`, { headers: wcAuthHeaders() }));
    return ok('woocommerce_system_status', base, {
      environment: data.environment,
      database: data.database,
      activePlugins: (data.active_plugins || []).map((p) => p.plugin),
      theme: data.theme,
      settings: data.settings,
    }, { durationMs });
  },

  async woocommerce_webhooks({ limit = 20 }) {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/webhooks?per_page=${cap}`, { headers: wcAuthHeaders() }));
    return ok('woocommerce_webhooks', base, { count: data.length, webhooks: data.map((w) => ({ id: w.id, name: w.name, status: w.status, topic: w.topic, deliveryUrl: w.delivery_url, dateCreated: w.date_created, dateModified: w.date_modified })) }, { durationMs });
  },

  async woocommerce_orders({ status = 'any', limit = 20 }) {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/orders?per_page=${cap}&status=${encodeURIComponent(status)}`, { headers: wcAuthHeaders() }));
    return ok('woocommerce_orders', base, { count: data.length, status, orders: data.map((o) => ({ id: o.id, number: o.number, status: o.status, total: o.total, currency: o.currency, dateCreated: o.date_created, customer: o.billing?.email || null })) }, { durationMs });
  },

  async woocommerce_products({ limit = 20 }) {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/products?per_page=${cap}`, { headers: wcAuthHeaders() }));
    return ok('woocommerce_products', base, { count: data.length, products: data.map((p) => ({ id: p.id, name: p.name, slug: p.slug, status: p.status, type: p.type, sku: p.sku, price: p.price, regularPrice: p.regular_price, salePrice: p.sale_price, stockStatus: p.stock_status, stockQuantity: p.stock_quantity, totalSales: p.total_sales })) }, { durationMs });
  },

  async woocommerce_gateways() {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const { value: data, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/payment_gateways`, { headers: wcAuthHeaders() }));
    return ok('woocommerce_gateways', base, { count: data.length, gateways: data.map((g) => ({ id: g.id, title: g.title, description: g.description, enabled: g.enabled, methodTitle: g.method_title, methodDescription: g.method_description, order: g.order })) }, { durationMs });
  },

  async woocommerce_shipping() {
    const base = configuredBase('WOOCOMMERCE_BASE_URL');
    const { value: zones, durationMs } = await withTiming(() => fetchJson(`${base}/wp-json/wc/v3/shipping/zones`, { headers: wcAuthHeaders() }));
    const enriched = [];
    for (const z of zones) {
      const methods = await fetchJson(`${base}/wp-json/wc/v3/shipping/zones/${z.id}/methods`, { headers: wcAuthHeaders() }).catch(() => []);
      enriched.push({ id: z.id, name: z.name, order: z.order, methods: methods.map((m) => ({ id: m.id, title: m.title, enabled: m.enabled, methodId: m.method_id, methodTitle: m.method_title })) });
    }
    return ok('woocommerce_shipping', base, { count: zones.length, zones: enriched }, { durationMs });
  },

  // -- Docker ---------------------------------------------------------------

  async docker_ps() {
    const { stdout } = await execFileAsync('docker', ['ps', '-a', '--format', '{{json .}}'], { timeout: 10_000, maxBuffer: 2_000_000 });
    const containers = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_ps', 'local', { count: containers.length, containers: containers.map((c) => ({ id: c.ID, name: c.Names, image: c.Image, state: c.State, status: c.Status, ports: c.Ports, created: c.CreatedAt })) });
  },

  async docker_inspect({ container }) {
    if (!/^[A-Za-z0-9_.-]+$/.test(container)) throw new Error('Invalid container name.');
    const { stdout } = await execFileAsync('docker', ['inspect', container], { timeout: 10_000, maxBuffer: 2_000_000 });
    const parsed = JSON.parse(stdout);
    if (!Array.isArray(parsed) || !parsed.length) throw new Error('Container not found.');
    const c = parsed[0];
    return ok('docker_inspect', container, {
      id: c.Id,
      name: c.Name,
      image: c.Config?.Image,
      state: c.State?.Status,
      created: c.Created,
      mounts: (c.Mounts || []).map((m) => ({ type: m.Type, source: m.Source, destination: m.Destination, mode: m.Mode, rw: m.RW })),
      network: Object.keys(c.NetworkSettings?.Networks || {}),
      env: (c.Config?.Env || []).filter((e) => !/^(_|PATH=|HOSTNAME=|HOME=|TERM=)/.test(e)).map((e) => {
        const idx = e.indexOf('=');
        const k = idx >= 0 ? e.slice(0, idx) : e;
        const v = idx >= 0 ? e.slice(idx + 1) : '';
        if (/secret|token|key|password|api/i.test(k)) return `${k}=<redacted>`;
        return e;
      }),
      exposedPorts: Object.keys(c.Config?.ExposedPorts || {}),
      restartPolicy: c.HostConfig?.RestartPolicy,
    });
  },

  async docker_logs({ container, lines = 100 }) {
    if (!/^[A-Za-z0-9_.-]+$/.test(container)) throw new Error('Invalid container name.');
    const cap = Math.min(Math.max(Number(lines) || 100, 1), 500);
    const { stdout, stderr } = await execFileAsync('docker', ['logs', '--tail', String(cap), container], { timeout: 10_000, maxBuffer: 2_000_000 });
    return ok('docker_logs', container, { container, lines: cap, stdout, stderr, stdoutSize: Buffer.byteLength(stdout), stderrSize: Buffer.byteLength(stderr) });
  },

  async docker_stats() {
    const { stdout } = await execFileAsync('docker', ['stats', '--no-stream', '--format', '{{json .}}'], { timeout: 10_000, maxBuffer: 2_000_000 });
    const lines = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_stats', 'local', { count: lines.length, containers: lines.map((c) => ({ name: c.Name, id: c.ID, cpuPerc: c.CPUPerc, memUsage: c.MemUsage, memPerc: c.MemPerc, netIO: c.NetIO, blockIO: c.BlockIO, pids: c.PIDs })) });
  },

  async docker_images() {
    const { stdout } = await execFileAsync('docker', ['images', '--format', '{{json .}}'], { timeout: 10_000, maxBuffer: 2_000_000 });
    const lines = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_images', 'local', { count: lines.length, images: lines.map((i) => ({ repository: i.Repository, tag: i.Tag, id: i.ID, size: i.Size, createdSince: i.CreatedSince, createdAt: i.CreatedAt })) });
  },

  async docker_networks() {
    const { stdout } = await execFileAsync('docker', ['network', 'ls', '--format', '{{json .}}'], { timeout: 10_000, maxBuffer: 2_000_000 });
    const lines = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_networks', 'local', { count: lines.length, networks: lines.map((n) => ({ id: n.ID, name: n.Name, driver: n.Driver, scope: n.Scope })) });
  },

  async docker_volumes() {
    const { stdout } = await execFileAsync('docker', ['volume', 'ls', '--format', '{{json .}}'], { timeout: 10_000, maxBuffer: 2_000_000 });
    const lines = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_volumes', 'local', { count: lines.length, volumes: lines.map((v) => ({ name: v.Name, driver: v.Driver, scope: v.Scope, size: v.Size, mountpoint: v.Mountpoint })) });
  },

  async docker_compose_status() {
    let stdout;
    try {
      ({ stdout } = await execFileAsync('docker', ['compose', 'ps', '--format', 'json'], { timeout: 10_000, maxBuffer: 2_000_000 }));
    } catch {
      try {
        ({ stdout } = await execFileAsync('docker-compose', ['ps', '--format', 'json'], { timeout: 10_000, maxBuffer: 2_000_000 }));
      } catch (e) {
        return ok('docker_compose_status', 'local', { present: false, error: e.message });
      }
    }
    const lines = stdout.trim() ? stdout.trim().split(/\r?\n/).map((l) => JSON.parse(l)) : [];
    return ok('docker_compose_status', 'local', { present: true, count: lines.length, services: lines.map((s) => ({ name: s.Name || s.Service, service: s.Service, state: s.State, status: s.Status, ports: s.Ports || s.Publishers })) });
  },
};

export default handlers;
