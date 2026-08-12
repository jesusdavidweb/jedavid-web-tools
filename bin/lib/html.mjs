// bin/lib/html.mjs
// HTML parsing, page model, and findings generators.
// Zero npm dependencies — part of the portable plugin runtime.

import { mkFinding, SEVERITY } from './runtime.mjs';

// HTML parsing primitives. We avoid a full HTML parser to keep the runtime
// dependency-free, but the patterns below are conservative and tolerant of
// malformed markup.

export function tagAttrs(tag) {
  const out = {};
  // Strip the leading '<' and tag name so the first match isn't the tag name.
  const inner = tag.replace(/^<\s*[a-zA-Z][\w:-]*/, '');
  const re = /([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(inner)) !== null) {
    if (m[2] === undefined && m[3] === undefined && m[4] === undefined) {
      out[m[1].toLowerCase()] = '';
    } else {
      out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
    }
  }
  return out;
}

export function tags(html, name) {
  if (!html) return [];
  const re = new RegExp(`<${name}\\b[^>]*>`, 'gi');
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    out.push({ tag: m[0], attrs: tagAttrs(m[0]) });
  }
  return out;
}

export function count(html, re) {
  if (!html) return 0;
  return [...html.matchAll(re)].length;
}

export function first(html, re, group = 1) {
  if (!html) return null;
  const m = html.match(re);
  if (!m) return null;
  const v = m[group];
  return typeof v === 'string' ? (v.trim() || null) : null;
}

export function uniqueUrls(list) {
  const seen = new Set();
  const out = [];
  for (const u of list) {
    if (!u) continue;
    if (seen.has(u)) continue;
    seen.add(u);
    out.push(u);
  }
  return out;
}

// Build a comprehensive page model from raw HTML.
export function pageModel(html, base) {
  if (!html) html = '';
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  let title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : null;
  if (title) title = title.slice(0, 1024);

  const metaTags = tags(html, 'meta');
  const linkTags = tags(html, 'link');
  const imgTags = tags(html, 'img');
  const scriptTags = tags(html, 'script');
  const styleTags = tags(html, 'style');
  const iframeTags = tags(html, 'iframe');

  const meta = (name) => metaTags.find((x) => (x.attrs.name || '').toLowerCase() === name)?.attrs.content || null;
  const metaProperty = (prop) => metaTags.find((x) => (x.attrs.property || '').toLowerCase() === prop)?.attrs.content || null;

  const canonicalLink = linkTags.find((x) => (x.attrs.rel || '').toLowerCase().split(/\s+/).includes('canonical'));
  const canonical = canonicalLink?.attrs.href || null;
  const amphtml = linkTags.find((x) => (x.attrs.rel || '').toLowerCase() === 'amphtml')?.attrs.href || null;

  const lang = first(html, /<html\b[^>]*\blang\s*=\s*["']([^"']+)["']/i);

  const description = meta('description');
  const robots = meta('robots');
  const googlebot = meta('googlebot');
  const viewport = metaTags.some((x) => (x.attrs.name || '').toLowerCase() === 'viewport');
  const keywords = meta('keywords');
  const author = meta('author');
  const generator = meta('generator');
  const themeColor = meta('theme-color');

  const og = {
    title: metaProperty('og:title'),
    description: metaProperty('og:description'),
    image: metaProperty('og:image'),
    url: metaProperty('og:url'),
    type: metaProperty('og:type'),
    site_name: metaProperty('og:site_name'),
    locale: metaProperty('og:locale'),
  };
  const twitter = {
    card: metaProperty('twitter:card') || meta('twitter:card'),
    title: metaProperty('twitter:title') || meta('twitter:title'),
    description: metaProperty('twitter:description') || meta('twitter:description'),
    image: metaProperty('twitter:image') || meta('twitter:image'),
    site: metaProperty('twitter:site') || meta('twitter:site'),
  };

  const hreflangs = linkTags
    .filter((x) => x.attrs.hreflang)
    .map((x) => ({ lang: x.attrs.hreflang, href: x.attrs.href }));

  const stylesheets = linkTags.filter((x) => (x.attrs.rel || '').toLowerCase() === 'stylesheet');
  const preload = linkTags.filter((x) => (x.attrs.rel || '').toLowerCase().split(/\s+/).includes('preload'));
  const preconnect = linkTags.filter((x) => (x.attrs.rel || '').toLowerCase() === 'preconnect');
  const modulepreload = linkTags.filter((x) => (x.attrs.rel || '').toLowerCase() === 'modulepreload');
  const dnsprefetch = linkTags.filter((x) => (x.attrs.rel || '').toLowerCase() === 'dns-prefetch');
  const pagination = {
    prev: linkTags.find((x) => (x.attrs.rel || '').toLowerCase() === 'prev')?.attrs.href || null,
    next: linkTags.find((x) => (x.attrs.rel || '').toLowerCase() === 'next')?.attrs.href || null,
  };

  const scripts = scriptTags
    .map((s) => {
      const type = (s.attrs.type || '').toLowerCase();
      const isJsonLd = type === 'application/ld+json';
      return { src: s.attrs.src || null, type: s.attrs.type || null, async: 'async' in s.attrs, defer: 'defer' in s.attrs, inline: !s.attrs.src, jsonLd: isJsonLd, content: s.attrs.src || isJsonLd ? null : s.tag.replace(/^<script[^>]*>/i, '').replace(/<\/script>$/i, '').slice(0, 2000) };
    })
    .filter((s) => s.src || s.inline);

  const inlineStyles = styleTags.length;
  const stylesheetHrefs = stylesheets.map((s) => s.attrs.href).filter(Boolean);

  const images = imgTags.map((i) => ({
    src: i.attrs.src || null,
    alt: 'alt' in i.attrs ? i.attrs.alt : null,
    width: i.attrs.width || null,
    height: i.attrs.height || null,
    loading: i.attrs.loading || null,
    decoding: i.attrs.decoding || null,
    fetchpriority: i.attrs.fetchpriority || null,
    srcset: i.attrs.srcset || null,
    sizes: i.attrs.sizes || null,
  }));

  const iframes = iframeTags.map((f) => ({ src: f.attrs.src || null, title: f.attrs.title || null }));

  const jsonLdCount = count(html, /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>/gi);
  const microdataCount = count(html, /<[^>]+itemtype\s*=\s*["']https?:\/\/schema\.org/gi);
  const rdfaCount = count(html, /<[^>]+typeof\s*=\s*["'][^"']+["']/gi);

  return {
    title, description, keywords, author, generator, themeColor,
    canonical, amphtml,
    lang, robots, googlebot, viewport,
    og, twitter,
    hreflangs,
    pagination,
    preload: preload.map((p) => p.attrs.href),
    preconnect: preconnect.map((p) => p.attrs.href),
    modulepreload: modulepreload.map((p) => p.attrs.href),
    dnsPrefetch: dnsprefetch.map((p) => p.attrs.href),
    headings: {
      h1: count(html, /<h1\b/gi),
      h2: count(html, /<h2\b/gi),
      h3: count(html, /<h3\b/gi),
      h4: count(html, /<h4\b/gi),
      h5: count(html, /<h5\b/gi),
      h6: count(html, /<h6\b/gi),
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
    jsonLdBlocks: scripts.filter((s) => s.jsonLd).length,
    scriptRenderBlocking: scripts.filter((s) => s.src && !s.async && !s.defer).length,
    stylesheetCount: stylesheets.length,
    stylesheetHrefs,
    inlineStyles,
    iframes,
    iframeCount: iframes.length,
    iframesMissingTitle: iframes.filter((f) => !f.title).length,
    jsonLdCount,
    microdataCount,
    rdfaCount,
    forms: count(html, /<form\b/gi),
    inputs: count(html, /<input\b/gi),
    labels: count(html, /<label\b/gi),
    buttons: count(html, /<button\b/gi),
    landmarks: {
      main: count(html, /<(?:main|role\s*=\s*["']main["'])[^>]*>/gi),
      nav: count(html, /<(?:nav|role\s*=\s*["']navigation["'])[^>]*>/gi),
      header: count(html, /<(?:header|role\s*=\s*["']banner["'])[^>]*>/gi),
      footer: count(html, /<(?:footer|role\s*=\s*["']contentinfo["'])[^>]*>/gi),
      aside: count(html, /<(?:aside|role\s*=\s*["']complementary["'])[^>]*>/gi),
      section: count(html, /<section\b/gi),
      article: count(html, /<article\b/gi),
    },
    skipLinks: count(html, /<a\b[^>]*href\s*=\s*["']#[^"']+["'][^>]*>[^<]*(?:skip|jump to|go to)/gi),
  };
}

// JSON-LD extraction
export function extractJsonLdBlocks(html) {
  if (!html) return [];
  const re = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1].trim();
    if (!raw) continue;
    try {
      const data = JSON.parse(raw);
      out.push({ raw, valid: true, data });
    } catch (e) {
      out.push({ raw: raw.slice(0, 4000), valid: false, error: e.message });
    }
  }
  return out;
}

// Flatten a JSON-LD payload (with @graph support) into a list of typed nodes.
export function flattenJsonLd(data) {
  if (data == null) return [];
  if (Array.isArray(data)) return data.flatMap(flattenJsonLd);
  if (typeof data !== 'object') return [];
  const nodes = [];
  if (data['@graph']) {
    nodes.push(...flattenJsonLd(data['@graph']));
  } else {
    nodes.push(data);
  }
  return nodes;
}

export function nodeType(node) {
  if (!node) return null;
  const t = node['@type'];
  if (Array.isArray(t)) return t[0] || null;
  return t || null;
}

export function nodeAllTypes(node) {
  if (!node) return [];
  const t = node['@type'];
  if (Array.isArray(t)) return t;
  if (t) return [t];
  return [];
}

// Extract anchor links with metadata.
export function extractAnchors(html, base) {
  if (!html) return [];
  const re = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    const a = tagAttrs(`<a ${m[1]}>`);
    if (!a.href) continue;
    let absolute = null;
    try { absolute = new URL(a.href, base).toString(); } catch { absolute = null; }
    const text = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
    const rel = (a.rel || '').toLowerCase().split(/\s+/).filter(Boolean);
    out.push({
      href: a.href,
      absolute,
      text,
      title: a.title || null,
      rel,
      nofollow: rel.includes('nofollow'),
      sponsored: rel.includes('sponsored'),
      ugc: rel.includes('ugc'),
      internal: absolute ? new URL(absolute).origin === new URL(base).origin : null,
    });
  }
  return out;
}

// Findings generators
// -------------------

// SEO findings
export function seoFindings(m) {
  const f = [];
  if (!m.title) {
    f.push(mkFinding({ id: 'seo.title.missing', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Missing <title>', description: 'The page has no non-empty <title>.', recommendation: 'Add a unique, descriptive title (50-60 characters is a common heuristic).' }));
  } else if (m.title.length < 10) {
    f.push(mkFinding({ id: 'seo.title.short', severity: SEVERITY.LOW, category: 'seo', title: 'Short title', description: `The title is only ${m.title.length} characters.`, recommendation: 'Use a more descriptive title.' }));
  } else if (m.title.length > 65) {
    f.push(mkFinding({ id: 'seo.title.long', severity: SEVERITY.LOW, category: 'seo', title: 'Long title', description: `The title is ${m.title.length} characters.`, recommendation: 'Consider trimming under 60 characters so it is not truncated in search results.' }));
  }

  if (!m.description) {
    f.push(mkFinding({ id: 'seo.description.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Missing meta description', description: 'No meta description was found.', recommendation: 'Add a page-specific description of roughly 120-160 characters.' }));
  } else if (m.description.length > 200) {
    f.push(mkFinding({ id: 'seo.description.long', severity: SEVERITY.LOW, category: 'seo', title: 'Long meta description', description: `Meta description is ${m.description.length} characters.`, recommendation: 'Keep it under 160 characters to avoid truncation.' }));
  }

  if (!m.canonical) {
    f.push(mkFinding({ id: 'seo.canonical.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Missing canonical', description: 'No <link rel="canonical"> was found.', recommendation: 'Add a self-referencing or intentionally consolidated canonical URL.' }));
  }

  if (!m.lang) {
    f.push(mkFinding({ id: 'seo.lang.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Missing html[lang]', description: 'The root html element has no lang attribute.', recommendation: 'Declare the page language for search engines and assistive technology.' }));
  }

  if (m.headings.h1 === 0) {
    f.push(mkFinding({ id: 'seo.h1.missing', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Missing H1', description: 'No H1 was found on the page.', recommendation: 'Use a clear primary heading that describes the page topic.' }));
  } else if (m.headings.h1 > 1) {
    f.push(mkFinding({ id: 'seo.h1.multiple', severity: SEVERITY.INFO, category: 'seo', title: 'Multiple H1 headings', description: `${m.headings.h1} H1 headings were found.`, recommendation: 'Verify that the heading hierarchy communicates a clear primary topic.' }));
  }

  if (m.headings.h1 === 0 && (m.headings.h2 > 0 || m.headings.h3 > 0)) {
    f.push(mkFinding({ id: 'seo.headings.hierarchy', severity: SEVERITY.LOW, category: 'seo', title: 'Heading hierarchy skips levels', description: 'H1 is missing while deeper headings exist.', recommendation: 'Use a logical heading hierarchy starting with H1.' }));
  }

  if (m.robots && /\bnoindex\b/i.test(m.robots)) {
    f.push(mkFinding({ id: 'seo.robots.noindex', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Page is marked noindex', description: `robots meta: ${m.robots}`, recommendation: 'Confirm that excluding this URL from indexing is intentional.' }));
  }
  if (m.robots && /\bnofollow\b/i.test(m.robots)) {
    f.push(mkFinding({ id: 'seo.robots.nofollow', severity: SEVERITY.LOW, category: 'seo', title: 'Page links are nofollow', description: `robots meta: ${m.robots}`, recommendation: 'Verify that forcing nofollow on all internal links is intentional.' }));
  }

  if (!m.og.title && !m.og['og:title']) {
    f.push(mkFinding({ id: 'seo.og.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Open Graph metadata missing', description: 'No og:title was found.', recommendation: 'Add at minimum og:title, og:description, og:image and og:url.' }));
  }
  if (!m.og.image && !m.og['og:image']) {
    f.push(mkFinding({ id: 'seo.og.image.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Open Graph image missing', description: 'No og:image was found.', recommendation: 'Add an og:image (1200x630 is a common safe size) for richer previews.' }));
  }
  if (!m.twitter.card && !m.twitter['twitter:card']) {
    f.push(mkFinding({ id: 'seo.twitter.missing', severity: SEVERITY.LOW, category: 'seo', title: 'Twitter Card metadata missing', description: 'No twitter:card was found.', recommendation: 'Add at minimum twitter:card, twitter:title, twitter:description and twitter:image.' }));
  }

  if (m.jsonLdCount === 0 && m.microdataCount === 0 && m.rdfaCount === 0) {
    f.push(mkFinding({ id: 'seo.structured.missing', severity: SEVERITY.INFO, category: 'seo', title: 'No structured data found', description: 'No JSON-LD, Microdata or RDFa was detected.', recommendation: 'Add structured data when it accurately represents visible content and entities.' }));
  }

  if (m.hreflangs.length > 0) {
    const noSelf = !m.hreflangs.some((h) => h.lang && h.lang.toLowerCase() === 'x-default');
    if (noSelf) {
      f.push(mkFinding({ id: 'seo.hreflang.xdefault', severity: SEVERITY.INFO, category: 'seo', title: 'hreflang x-default missing', description: 'Multilingual page is missing an x-default hreflang.', recommendation: 'Add hreflang="x-default" pointing to the international/aggregator page.' }));
    }
  }

  if (m.imagesMissingAlt > 0) {
    f.push(mkFinding({ id: 'seo.images.alt.missing', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Images without alt', description: `${m.imagesMissingAlt} of ${m.imageCount} images lack alt attributes.`, recommendation: 'Add descriptive alt text or alt="" for decorative images.' }));
  }
  if (m.imagesMissingDimensions > 0) {
    f.push(mkFinding({ id: 'seo.images.dimensions', severity: SEVERITY.LOW, category: 'seo', title: 'Images without explicit dimensions', description: `${m.imagesMissingDimensions} images do not declare both width and height.`, recommendation: 'Reserve image aspect ratio to reduce layout shifts (CLS).' }));
  }

  return f;
}

// Performance findings
export function performanceFindings(m, { responseMs, htmlBytes, headers }) {
  const f = [];
  if (responseMs > 1000) {
    f.push(mkFinding({ id: 'perf.ttfb.slow', severity: responseMs > 2000 ? SEVERITY.HIGH : SEVERITY.MEDIUM, category: 'performance', title: 'Slow document response', description: `Initial response took ${responseMs} ms.`, recommendation: 'Inspect origin latency, caching, server-side work and edge delivery.' }));
  }
  if (htmlBytes > 200_000) {
    f.push(mkFinding({ id: 'perf.html.large', severity: htmlBytes > 500_000 ? SEVERITY.HIGH : SEVERITY.MEDIUM, category: 'performance', title: 'Large HTML document', description: `HTML response is ${(htmlBytes / 1024).toFixed(1)} KiB.`, recommendation: 'Reduce oversized inline payloads, duplicated markup and server-rendered fragments that could be hydrated later.' }));
  }
  if (m.scriptExternal > 20) {
    f.push(mkFinding({ id: 'perf.scripts.many', severity: SEVERITY.MEDIUM, category: 'performance', title: 'High script count', description: `${m.scriptExternal} external scripts were found.`, recommendation: 'Audit third-party scripts, bundle critical code and defer the rest.' }));
  }
  if (m.scriptRenderBlocking > 0) {
    f.push(mkFinding({ id: 'perf.scripts.render_blocking', severity: SEVERITY.MEDIUM, category: 'performance', title: 'Render-blocking scripts', description: `${m.scriptRenderBlocking} external scripts in the head without async or defer.`, recommendation: 'Add async or defer, or move them to the end of body.' }));
  }
  if (m.imageCount > 0 && m.imagesLazy === m.imageCount) {
    f.push(mkFinding({ id: 'perf.images.all_lazy', severity: SEVERITY.MEDIUM, category: 'performance', title: 'Every image is lazy-loaded', description: 'All images use loading="lazy", which can delay the above-the-fold LCP image.', recommendation: 'Avoid lazy-loading the primary above-the-fold image; consider fetchpriority="high".' }));
  }
  if (m.imagesMissingDimensions > 0) {
    f.push(mkFinding({ id: 'perf.images.cls', severity: SEVERITY.MEDIUM, category: 'performance', title: 'Images without explicit dimensions', description: `${m.imagesMissingDimensions} images do not declare width and height.`, recommendation: 'Reserve intrinsic aspect ratio to reduce CLS.' }));
  }
  if (!m.viewport) {
    f.push(mkFinding({ id: 'perf.viewport.missing', severity: SEVERITY.HIGH, category: 'performance', title: 'Missing viewport meta', description: 'No viewport meta tag was found.', recommendation: 'Add a responsive viewport declaration for mobile rendering.' }));
  }
  if (m.preload.length === 0 && (m.scriptExternal > 0 || m.stylesheetCount > 0)) {
    f.push(mkFinding({ id: 'perf.preload.missing', severity: SEVERITY.INFO, category: 'performance', title: 'No resource hints', description: 'No rel="preload" or rel="modulepreload" was used.', recommendation: 'Preload critical above-the-fold assets and fonts.' }));
  }
  if (m.preconnect.length === 0) {
    f.push(mkFinding({ id: 'perf.preconnect.missing', severity: SEVERITY.INFO, category: 'performance', title: 'No preconnect hints', description: 'No rel="preconnect" was used for third-party origins.', recommendation: 'Preconnect to required third-party origins to reduce TLS/DNS overhead.' }));
  }
  if (m.iframeCount > 0) {
    f.push(mkFinding({ id: 'perf.iframes', severity: SEVERITY.INFO, category: 'performance', title: 'Iframes detected', description: `${m.iframeCount} iframe(s) found.`, recommendation: 'Lazy-load non-critical iframes to reduce initial weight.' }));
  }
  // Header-based checks
  const ce = headers.get('content-encoding');
  if (ce && !/^(gzip|br|deflate|zstd)/i.test(ce)) {
    f.push(mkFinding({ id: 'perf.compression.uncommon', severity: SEVERITY.INFO, category: 'performance', title: 'Uncommon content encoding', description: `content-encoding: ${ce}`, recommendation: 'Verify that intermediaries and clients can decode this encoding.' }));
  }
  if (!headers.get('content-encoding') && htmlBytes > 5_000) {
    f.push(mkFinding({ id: 'perf.compression.missing', severity: SEVERITY.MEDIUM, category: 'performance', title: 'No content compression', description: 'Response does not advertise content-encoding.', recommendation: 'Enable gzip, brotli or zstd at the origin or edge.' }));
  }
  return f;
}

// Accessibility findings
export function accessibilityFindings(m) {
  const f = [];
  if (!m.lang) {
    f.push(mkFinding({ id: 'a11y.lang', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Missing html[lang]', description: 'Root html element has no lang attribute.', recommendation: 'Declare the page language to enable correct screen reader pronunciation and search engine signals.' }));
  }
  if (!m.title) {
    f.push(mkFinding({ id: 'a11y.title', severity: SEVERITY.HIGH, category: 'accessibility', title: 'Missing document title', description: 'A non-empty <title> is required for orientation.', recommendation: 'Add a descriptive, unique page title.' }));
  }
  if (!m.viewport) {
    f.push(mkFinding({ id: 'a11y.viewport', severity: SEVERITY.HIGH, category: 'accessibility', title: 'Missing viewport meta', description: 'Without a viewport meta tag the page is not mobile-accessible.', recommendation: 'Add a responsive viewport declaration.' }));
  }
  if (m.headings.h1 === 0) {
    f.push(mkFinding({ id: 'a11y.h1', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Missing H1', description: 'A single H1 helps establish page structure for assistive technology.', recommendation: 'Use a clear primary heading.' }));
  }
  if (m.imagesMissingAlt > 0) {
    f.push(mkFinding({ id: 'a11y.images.alt', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Images without alt', description: `${m.imagesMissingAlt} images do not declare alt.`, recommendation: 'Provide alt text or alt="" for decorative images.' }));
  }
  if (m.inputs > 0 && m.labels === 0) {
    f.push(mkFinding({ id: 'a11y.forms.labels', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Inputs without labels', description: `Found ${m.inputs} inputs but no <label> elements.`, recommendation: 'Use <label for="id"> or aria-label/aria-labelledby to associate a label with every input.' }));
  }
  if (m.iframesMissingTitle > 0) {
    f.push(mkFinding({ id: 'a11y.iframes.title', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Iframes without title', description: `${m.iframesMissingTitle} iframe(s) do not declare a title attribute.`, recommendation: 'Add a descriptive title to every iframe.' }));
  }
  if (m.landmarks.main === 0) {
    f.push(mkFinding({ id: 'a11y.landmarks.main', severity: SEVERITY.LOW, category: 'accessibility', title: 'No <main> landmark', description: 'A <main> landmark helps screen reader users skip to primary content.', recommendation: 'Wrap the primary content in a <main> element.' }));
  }
  if (m.landmarks.nav === 0) {
    f.push(mkFinding({ id: 'a11y.landmarks.nav', severity: SEVERITY.LOW, category: 'accessibility', title: 'No <nav> landmark', description: 'A <nav> landmark helps screen reader users find navigation.', recommendation: 'Wrap primary navigation in a <nav> element.' }));
  }
  if (m.skipLinks === 0) {
    f.push(mkFinding({ id: 'a11y.skip_link', severity: SEVERITY.LOW, category: 'accessibility', title: 'No skip navigation link', description: 'No "skip to content" link was detected near the top of the page.', recommendation: 'Provide a skip link as the first focusable element.' }));
  }
  return f;
}

// Security header findings
export function securityHeaderFindings(headers, isHttps) {
  const f = [];
  const check = (name, label, severity = SEVERITY.INFO, extra) => {
    if (!headers.has(name)) {
      f.push(mkFinding({ id: `security.headers.${name.replace(/-/g, '_')}.missing`, severity, category: 'security', title: `Missing ${label}`, description: extra?.description || `Response does not include ${label}.`, recommendation: extra?.recommendation || `Define an appropriate ${label} policy and test it before enforcing broadly.` }));
    }
  };

  check('content-security-policy', 'Content-Security-Policy', SEVERITY.MEDIUM, {
    description: 'No CSP header. Without CSP the impact of any XSS is amplified.',
    recommendation: 'Define a strict CSP starting with a report-only deployment.',
  });
  if (isHttps) check('strict-transport-security', 'Strict-Transport-Security', SEVERITY.MEDIUM, {
    description: 'HTTPS is used but HSTS is not advertised.',
    recommendation: 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload once verified.',
  });
  check('x-content-type-options', 'X-Content-Type-Options', SEVERITY.MEDIUM, {
    description: 'MIME sniffing is not blocked.',
    recommendation: 'Send X-Content-Type-Options: nosniff.',
  });
  check('referrer-policy', 'Referrer-Policy', SEVERITY.LOW, {
    description: 'Referrer policy is not set.',
    recommendation: 'Send Referrer-Policy: strict-origin-when-cross-origin or stricter.',
  });
  check('permissions-policy', 'Permissions-Policy', SEVERITY.LOW, {
    description: 'No Permissions-Policy header.',
    recommendation: 'Lock down powerful features (camera, microphone, geolocation, etc.).',
  });
  check('cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', SEVERITY.LOW);
  check('cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', SEVERITY.INFO);
  check('cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', SEVERITY.INFO);
  check('x-frame-options', 'X-Frame-Options', SEVERITY.LOW, {
    description: 'X-Frame-Options is not set. CSP frame-ancestors is the modern equivalent.',
    recommendation: 'Add frame-ancestors in CSP and/or X-Frame-Options: DENY where appropriate.',
  });
  check('x-permitted-cross-domain-policies', 'X-Permitted-Cross-Domain-Policies', SEVERITY.INFO);

  const server = headers.get('server');
  if (server && /\d/.test(server)) {
    f.push(mkFinding({ id: 'security.headers.server.disclosure', severity: SEVERITY.LOW, category: 'security', title: 'Server version disclosure', description: `Server: ${server}`, recommendation: 'Avoid leaking server version details where the stack allows it.' }));
  }
  const powered = headers.get('x-powered-by');
  if (powered) {
    f.push(mkFinding({ id: 'security.headers.x_powered_by', severity: SEVERITY.LOW, category: 'security', title: 'X-Powered-By disclosure', description: `X-Powered-By: ${powered}`, recommendation: 'Remove the X-Powered-By header at the edge or framework level.' }));
  }
  return f;
}

// Cookie security findings (uses raw Set-Cookie strings).
export function securityCookieFindings(cookies) {
  const f = [];
  for (const c of cookies) {
    const name = c.name || '(unnamed)';
    if (!c.secure && /^https:/i.test('')) {
      // We don't know the page scheme here; flag conditionally below.
    }
    if (!c.secure) {
      f.push(mkFinding({ id: 'security.cookies.secure.missing', severity: SEVERITY.MEDIUM, category: 'security', title: `Cookie "${name}" missing Secure`, description: `Set-Cookie: ${c.raw || ''}`, recommendation: 'Add the Secure attribute on cookies sent over HTTPS.' }));
    }
    if (!c.httpOnly) {
      f.push(mkFinding({ id: 'security.cookies.httponly.missing', severity: SEVERITY.MEDIUM, category: 'security', title: `Cookie "${name}" missing HttpOnly`, description: `Set-Cookie: ${c.raw || ''}`, recommendation: 'Add the HttpOnly attribute on cookies that do not need JavaScript access.' }));
    }
    if (!c.sameSite) {
      f.push(mkFinding({ id: 'security.cookies.samesite.missing', severity: SEVERITY.MEDIUM, category: 'security', title: `Cookie "${name}" missing SameSite`, description: `Set-Cookie: ${c.raw || ''}`, recommendation: 'Set SameSite=Lax (or Strict when appropriate) to mitigate CSRF.' }));
    }
  }
  return f;
}

// Stack detection — produces a list of detected technologies with evidence.
export function stackFindings(html, headers) {
  const out = [];
  const add = (name, evidence, confidence) => {
    if (out.some((o) => o.name === name)) return;
    out.push({ name, evidence, confidence });
  };

  const h = headersObjForFindings(headers);
  const H = html || '';

  if (/wp-content|wp-includes|wordpress/i.test(H)) add('WordPress', 'wp-content/wp-includes paths or generator meta', 'high');
  if (/woocommerce/i.test(H) || /woocommerce/i.test(h['link'] || '')) add('WooCommerce', 'WooCommerce script/style signatures', 'high');
  if (/shopify/i.test(H) || /cdn\.shopify\.com/i.test(H)) add('Shopify', 'Shopify CDN or storefront signature', 'high');
  if (/__NEXT_DATA__|\/_next\//i.test(H) || h['x-powered-by'] === 'Next.js') add('Next.js', '__NEXT_DATA__ or /_next/ assets', 'high');
  if (/astro-island|\/_astro\//i.test(H)) add('Astro', 'astro-island custom element or /_astro/ assets', 'high');
  if (/svelte/i.test(H) || /__sveltekit/i.test(H)) add('SvelteKit', 'Svelte runtime or SvelteKit signature', 'medium');
  if (/data-react-helmet|__NEXT_DATA__|react-root/i.test(H)) add('React', 'React root markers or framework signatures', 'medium');
  if (/data-vue|data-server-rendered|nuxt/i.test(H)) add('Vue / Nuxt', 'Vue/Nuxt markers', 'medium');
  if (/__NUXT__|nuxt/i.test(H)) add('Nuxt', 'Nuxt __NUXT__ payload', 'high');
  if (/data-svelte|astro|sveltekit/i.test(H)) add('Svelte / SvelteKit / Astro', 'Svelte-family markers', 'medium');
  // CDN / edge: detect by header *keys*, not by header *values*.
  if (h['cf-ray'] || h['cf-cache-status'] || h['cf-worker'] || /cdn-cgi/i.test(H)) add('Cloudflare', 'cf-ray, cf-cache-status or CDN-CGI evidence', 'high');
  if (h['x-vercel-id'] || h['x-vercel-cache'] || /vercel/i.test(H)) add('Vercel', 'Vercel headers or signatures', 'high');
  if (h['x-nf-request-id'] || /netlify/i.test(H)) add('Netlify', 'Netlify headers or signatures', 'high');
  if (h['x-amz-cf-id'] || /cloudfront/i.test(h['via'] || '')) add('AWS CloudFront', 'CloudFront headers or via signature', 'medium');
  if (/fastly/i.test(h['x-served-by'] || '') || /fastly/i.test(h['via'] || '') || /fastly/i.test(H)) add('Fastly', 'Fastly headers or signatures', 'medium');
  if (h['x-akamai-request-id'] || /akamai/i.test(h['via'] || '') || /akamai/i.test(h['server'] || '')) add('Akamai', 'Akamai headers or signatures', 'medium');
  if (h['fly-request-id'] || /fly\.io/i.test(H)) add('Fly.io', 'fly-request-id or fly.io signature', 'medium');

  if (/googletagmanager|gtag\(|google-analytics\.com/i.test(H)) add('Google Analytics / GTM', 'Analytics scripts', 'high');
  if (/connect\.facebook\.net|fbq\(/i.test(H)) add('Meta Pixel', 'Meta Pixel script', 'high');
  if (/hotjar\.com/i.test(H)) add('Hotjar', 'Hotjar script', 'high');
  if (/segment\.com|analytics\.js/i.test(H)) add('Segment', 'Segment analytics', 'high');
  if (/sentry\.io|sentry\.browser/i.test(H)) add('Sentry', 'Sentry browser SDK', 'high');
  if (/nginx/i.test(h['server'] || '')) add('nginx', `server: ${h['server']}`, 'high');
  if (/apache/i.test(h['server'] || '')) add('Apache', `server: ${h['server']}`, 'high');
  if (/iis/i.test(h['server'] || '')) add('Microsoft IIS', `server: ${h['server']}`, 'high');
  if (h['server']) add(h['server'], `server: ${h['server']}`, 'medium');
  if (h['x-powered-by']) add(h['x-powered-by'], `x-powered-by: ${h['x-powered-by']}`, 'medium');

  return out;
}

function headersObjForFindings(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) out[k.toLowerCase()] = v;
  return out;
}

// Indexability findings (combines HTML/headers/robots.txt)
export function indexabilityFindings({ status, robotsMeta, xRobotsTag, canonical, robotsTxt, finalUrl }) {
  const f = [];
  if (status < 200 || status >= 300) {
    f.push(mkFinding({ id: 'indexability.status', severity: SEVERITY.HIGH, category: 'indexability', title: 'Non-success HTTP status', description: `Final response: HTTP ${status}.`, recommendation: 'Resolve HTTP errors before assessing content.' }));
  }
  if (robotsMeta && /\bnoindex\b/i.test(robotsMeta)) {
    f.push(mkFinding({ id: 'indexability.noindex.meta', severity: SEVERITY.HIGH, category: 'indexability', title: 'Meta robots noindex', description: `robots meta: ${robotsMeta}`, recommendation: 'Confirm noindex is intentional.' }));
  }
  if (xRobotsTag && /\bnoindex\b/i.test(xRobotsTag)) {
    f.push(mkFinding({ id: 'indexability.noindex.header', severity: SEVERITY.HIGH, category: 'indexability', title: 'X-Robots-Tag noindex', description: `X-Robots-Tag: ${xRobotsTag}`, recommendation: 'Confirm noindex is intentional.' }));
  }
  if (robotsTxt && robotsTxt.disallow && robotsTxt.disallow.length > 0) {
    const blocksRoot = robotsTxt.disallow.some((d) => d === '/' || d === '');
    if (blocksRoot) {
      f.push(mkFinding({ id: 'indexability.robots.root', severity: SEVERITY.HIGH, category: 'indexability', title: 'robots.txt blocks crawling', description: 'robots.txt contains a Disallow: / rule.', recommendation: 'Confirm that blocking the entire site is intentional.' }));
    }
  }
  if (canonical && finalUrl) {
    try {
      const cu = new URL(canonical, finalUrl);
      const fu = new URL(finalUrl);
      if (cu.origin !== fu.origin) {
        f.push(mkFinding({ id: 'indexability.canonical.cross_origin', severity: SEVERITY.MEDIUM, category: 'indexability', title: 'Canonical points to a different origin', description: `Canonical: ${canonical} vs ${finalUrl}`, recommendation: 'Cross-origin canonicals are valid when consolidating signals, but verify intent.' }));
      }
    } catch {}
  }
  return f;
}

// LLM discoverability findings
export function llmFindings({ llmsTxt, robotsTxt, jsonLd, model }) {
  const f = [];
  if (!llmsTxt.present) {
    f.push(mkFinding({ id: 'llm.llms_txt.missing', severity: SEVERITY.INFO, category: 'llm', title: 'No llms.txt', description: 'No /llms.txt was returned by the origin.', recommendation: 'llms.txt is an emerging convention, not a standard. Consider publishing one if you want to make authoritative content easy for LLM tooling to ingest.' }));
  } else {
    if (llmsTxt.preview) {
      const size = llmsTxt.preview.length;
      if (size < 200) {
        f.push(mkFinding({ id: 'llm.llms_txt.thin', severity: SEVERITY.INFO, category: 'llm', title: 'llms.txt is thin', description: `llms.txt returned only ${size} characters.`, recommendation: 'List the most important documentation and entity pages with short, accurate descriptions.' }));
      }
    }
  }
  if (model && !model.lang) {
    f.push(mkFinding({ id: 'llm.lang.missing', severity: SEVERITY.LOW, category: 'llm', title: 'No html[lang]', description: 'Without a declared language, LLM-based parsers may mis-classify the content.', recommendation: 'Declare the page language.' }));
  }
  if (!jsonLd || jsonLd.length === 0) {
    f.push(mkFinding({ id: 'llm.structured.missing', severity: SEVERITY.LOW, category: 'llm', title: 'No structured data', description: 'No JSON-LD was detected. Structured data is one of the most reliable signals for LLM-based extractors.', recommendation: 'Add Organization, WebSite, Article, Product or FAQPage JSON-LD that matches visible content.' }));
  }
  if (model && !model.description) {
    f.push(mkFinding({ id: 'llm.description.missing', severity: SEVERITY.INFO, category: 'llm', title: 'No meta description', description: 'Meta description is a reliable summary for LLM-based systems.', recommendation: 'Add a useful page-specific meta description.' }));
  }
  // AI crawler directives (informational)
  const aiBots = ['GPTBot', 'OAI-SearchBot', 'ClaudeBot', 'Google-Extended', 'PerplexityBot', 'ChatGPT-User', 'Applebot-Extended', 'Bytespider', 'CCBot'];
  if (robotsTxt && robotsTxt.userAgents) {
    const ua = robotsTxt.userAgents.map((u) => u.toLowerCase());
    const blocked = aiBots.filter((b) => ua.includes(b.toLowerCase()));
    if (blocked.length) {
      f.push(mkFinding({ id: 'llm.ai_bots.blocked', severity: SEVERITY.INFO, category: 'llm', title: 'AI crawlers explicitly named in robots.txt', description: `AI crawlers mentioned: ${blocked.join(', ')}`, recommendation: 'Confirm that the AI crawler directives reflect your intent for each bot.' }));
    }
  }
  return f;
}

// Link findings
export function linkFindings(anchors) {
  const f = [];
  const internal = anchors.filter((a) => a.internal === true);
  const external = anchors.filter((a) => a.internal === false);
  const emptyText = anchors.filter((a) => !a.text);
  const nofollow = anchors.filter((a) => a.nofollow);
  const generic = anchors.filter((a) => /^(click here|here|read more|more|learn more|this)$/i.test(a.text || ''));

  if (anchors.length === 0) {
    f.push(mkFinding({ id: 'links.empty', severity: SEVERITY.LOW, category: 'seo', title: 'No anchor links found', description: 'The page contains no <a> elements.', recommendation: 'Internal links help crawlers and users navigate the site.' }));
  }
  if (emptyText.length > 0) {
    f.push(mkFinding({ id: 'links.empty_text', severity: SEVERITY.MEDIUM, category: 'accessibility', title: 'Links without visible text', description: `${emptyText.length} anchor(s) have no link text.`, recommendation: 'Use descriptive link text or aria-label.' }));
  }
  if (generic.length > 0) {
    f.push(mkFinding({ id: 'links.generic_text', severity: SEVERITY.LOW, category: 'seo', title: 'Generic link text', description: `${generic.length} anchor(s) use generic text (e.g. "click here", "read more").`, recommendation: 'Use descriptive, context-bearing link text.' }));
  }
  if (nofollow.length > 0 && internal.length > 0 && nofollow.length === anchors.length) {
    f.push(mkFinding({ id: 'links.all_nofollow', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Every link is nofollow', description: 'All anchor links are marked rel="nofollow".', recommendation: 'Confirm this is intentional; it can suppress internal PageRank flow.' }));
  }
  return f;
}

// Schema findings (parses JSON-LD blocks)
export function schemaFindings(blocks) {
  const f = [];
  if (!blocks || blocks.length === 0) {
    f.push(mkFinding({ id: 'schema.missing', severity: SEVERITY.LOW, category: 'seo', title: 'No JSON-LD found', description: 'No application/ld+json script blocks were detected.', recommendation: 'Add structured data for the primary entities on the page.' }));
    return f;
  }
  const invalid = blocks.filter((b) => !b.valid);
  if (invalid.length > 0) {
    f.push(mkFinding({ id: 'schema.invalid', severity: SEVERITY.MEDIUM, category: 'seo', title: 'Invalid JSON-LD', description: `${invalid.length} JSON-LD block(s) failed to parse.`, recommendation: 'Fix JSON syntax and verify with the Rich Results Test.' }));
  }
  const seen = new Set();
  for (const b of blocks.filter((b) => b.valid).flatMap((b) => flattenJsonLd(b.data))) {
    const t = nodeType(b);
    if (t && !seen.has(t)) seen.add(t);
  }
  if (seen.size === 0) {
    f.push(mkFinding({ id: 'schema.typeless', severity: SEVERITY.LOW, category: 'seo', title: 'JSON-LD without @type', description: 'No @type was declared in any JSON-LD node.', recommendation: 'Each node should declare a schema.org @type.' }));
  }
  return f;
}
