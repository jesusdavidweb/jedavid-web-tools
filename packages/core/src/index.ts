import * as cheerio from 'cheerio';

export type AuditCategory = 'performance' | 'seo' | 'security';
export type Severity = 'info' | 'warning' | 'error';

export interface AuditFinding {
  category: AuditCategory;
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation?: string;
}

export interface AuditResult {
  url: string;
  finalUrl: string;
  status: number;
  fetchedAt: string;
  timing: {
    responseMs: number;
  };
  document: {
    htmlBytes: number;
    title: string | null;
    metaDescription: string | null;
    canonical: string | null;
    lang: string | null;
    h1Count: number;
    scriptCount: number;
    stylesheetCount: number;
    imageCount: number;
    lazyImageCount: number;
    imagesMissingDimensions: number;
    schemaBlocks: number;
  };
  headers: Record<string, string>;
  findings: AuditFinding[];
  summary: {
    errors: number;
    warnings: number;
    info: number;
  };
}

export interface AuditOptions {
  categories?: AuditCategory[];
  timeoutMs?: number;
  userAgent?: string;
}

const DEFAULT_CATEGORIES: AuditCategory[] = ['performance', 'seo', 'security'];

function normalizeUrl(input: string): URL {
  const candidate = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  const url = new URL(candidate);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP and HTTPS URLs are supported.');
  }
  return url;
}

function headerRecord(headers: Headers): Record<string, string> {
  return Object.fromEntries([...headers.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

function pushPerformanceFindings(
  findings: AuditFinding[],
  responseMs: number,
  htmlBytes: number,
  scriptCount: number,
  imageCount: number,
  lazyImageCount: number,
  imagesMissingDimensions: number,
  hasViewport: boolean,
): void {
  if (responseMs > 1000) {
    findings.push({
      category: 'performance',
      id: 'slow-document-response',
      severity: responseMs > 2000 ? 'error' : 'warning',
      title: 'Slow initial document response',
      detail: `The HTML document response took ${responseMs} ms.`,
      recommendation: 'Inspect origin latency, caching, database work and edge delivery before optimizing frontend assets.',
    });
  }

  if (htmlBytes > 200_000) {
    findings.push({
      category: 'performance',
      id: 'large-html-document',
      severity: 'warning',
      title: 'Large HTML document',
      detail: `The HTML response is ${(htmlBytes / 1024).toFixed(1)} KiB.`,
      recommendation: 'Reduce duplicated markup, oversized inline payloads and unnecessary server-rendered content.',
    });
  }

  if (scriptCount > 20) {
    findings.push({
      category: 'performance',
      id: 'high-script-count',
      severity: 'warning',
      title: 'High script count',
      detail: `${scriptCount} script elements were found in the initial HTML.`,
      recommendation: 'Review third-party scripts, code splitting and hydration strategy.',
    });
  }

  if (imageCount > 0 && lazyImageCount === imageCount) {
    findings.push({
      category: 'performance',
      id: 'all-images-lazy',
      severity: 'warning',
      title: 'Every image is lazy-loaded',
      detail: 'All images in the document use loading="lazy", which can delay an above-the-fold LCP image.',
      recommendation: 'Do not lazy-load the primary above-the-fold/LCP image; consider fetchpriority="high" when appropriate.',
    });
  }

  if (imagesMissingDimensions > 0) {
    findings.push({
      category: 'performance',
      id: 'images-missing-dimensions',
      severity: 'warning',
      title: 'Images without explicit dimensions',
      detail: `${imagesMissingDimensions} image(s) do not declare both width and height attributes.`,
      recommendation: 'Reserve image aspect ratio to reduce layout shifts.',
    });
  }

  if (!hasViewport) {
    findings.push({
      category: 'performance',
      id: 'missing-viewport',
      severity: 'error',
      title: 'Missing viewport meta tag',
      detail: 'No viewport meta tag was found.',
      recommendation: 'Add a responsive viewport declaration for mobile rendering.',
    });
  }
}

function pushSeoFindings(
  findings: AuditFinding[],
  title: string | null,
  metaDescription: string | null,
  canonical: string | null,
  lang: string | null,
  h1Count: number,
  robots: string | null,
  schemaBlocks: number,
): void {
  if (!title) {
    findings.push({ category: 'seo', id: 'missing-title', severity: 'error', title: 'Missing title', detail: 'The page has no non-empty <title>.', recommendation: 'Add a unique, descriptive title.' });
  } else if (title.length > 65) {
    findings.push({ category: 'seo', id: 'long-title', severity: 'warning', title: 'Long title', detail: `The title is ${title.length} characters long.`, recommendation: 'Keep the title concise while preserving search intent and entity clarity.' });
  }

  if (!metaDescription) {
    findings.push({ category: 'seo', id: 'missing-meta-description', severity: 'warning', title: 'Missing meta description', detail: 'No non-empty meta description was found.', recommendation: 'Add a useful page-specific description.' });
  }

  if (!canonical) {
    findings.push({ category: 'seo', id: 'missing-canonical', severity: 'warning', title: 'Missing canonical URL', detail: 'No canonical link element was found.', recommendation: 'Add a self-referencing or intentionally consolidated canonical URL.' });
  }

  if (!lang) {
    findings.push({ category: 'seo', id: 'missing-lang', severity: 'warning', title: 'Missing document language', detail: 'The root html element has no lang attribute.', recommendation: 'Declare the page language for search engines and assistive technology.' });
  }

  if (h1Count === 0) {
    findings.push({ category: 'seo', id: 'missing-h1', severity: 'warning', title: 'Missing H1', detail: 'No H1 heading was found.', recommendation: 'Use a clear primary heading that describes the page topic.' });
  } else if (h1Count > 1) {
    findings.push({ category: 'seo', id: 'multiple-h1', severity: 'info', title: 'Multiple H1 headings', detail: `${h1Count} H1 headings were found.`, recommendation: 'Verify that the heading hierarchy communicates a clear primary topic.' });
  }

  if (robots && /\bnoindex\b/i.test(robots)) {
    findings.push({ category: 'seo', id: 'noindex', severity: 'warning', title: 'Page is marked noindex', detail: `robots meta content: ${robots}`, recommendation: 'Confirm that excluding this URL from indexing is intentional.' });
  }

  if (schemaBlocks === 0) {
    findings.push({ category: 'seo', id: 'missing-jsonld', severity: 'info', title: 'No JSON-LD structured data found', detail: 'No application/ld+json script was found.', recommendation: 'Add relevant structured data when it accurately represents visible content and entities.' });
  }
}

function pushSecurityFindings(findings: AuditFinding[], headers: Headers, finalUrl: URL): void {
  const checks: Array<[string, string, string]> = [
    ['content-security-policy', 'missing-csp', 'Content-Security-Policy'],
    ['x-content-type-options', 'missing-nosniff', 'X-Content-Type-Options'],
    ['referrer-policy', 'missing-referrer-policy', 'Referrer-Policy'],
    ['permissions-policy', 'missing-permissions-policy', 'Permissions-Policy'],
  ];

  if (finalUrl.protocol === 'https:' && !headers.has('strict-transport-security')) {
    findings.push({ category: 'security', id: 'missing-hsts', severity: 'warning', title: 'Missing Strict-Transport-Security', detail: 'HTTPS is in use but HSTS was not returned.', recommendation: 'Enable HSTS after confirming every required subdomain is HTTPS-ready.' });
  }

  for (const [header, id, label] of checks) {
    if (!headers.has(header)) {
      findings.push({ category: 'security', id, severity: header === 'content-security-policy' ? 'warning' : 'info', title: `Missing ${label}`, detail: `The response does not include ${label}.`, recommendation: `Define an appropriate ${label} policy and test it before enforcing broadly.` });
    }
  }

  const server = headers.get('server');
  if (server && /\d/.test(server)) {
    findings.push({ category: 'security', id: 'server-version-disclosure', severity: 'info', title: 'Server version disclosure', detail: `Server header: ${server}`, recommendation: 'Avoid exposing unnecessary server version details where your stack allows it.' });
  }
}

export async function auditSite(input: string, options: AuditOptions = {}): Promise<AuditResult> {
  const url = normalizeUrl(input);
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
        'user-agent': options.userAgent ?? 'jedavid-web-tools/0.1 (+https://github.com/jesusdavidweb/jedavid-web-tools)',
        accept: 'text/html,application/xhtml+xml',
      },
    });
  } finally {
    clearTimeout(timeout);
  }

  const responseMs = Math.round(performance.now() - started);
  const html = await response.text();
  const htmlBytes = Buffer.byteLength(html);
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim() || null;
  const metaDescription = $('meta[name="description"]').first().attr('content')?.trim() || null;
  const canonical = $('link[rel="canonical"]').first().attr('href')?.trim() || null;
  const lang = $('html').first().attr('lang')?.trim() || null;
  const robots = $('meta[name="robots"]').first().attr('content')?.trim() || null;
  const h1Count = $('h1').length;
  const scriptCount = $('script[src]').length;
  const stylesheetCount = $('link[rel="stylesheet"]').length;
  const images = $('img');
  const imageCount = images.length;
  const lazyImageCount = images.filter('[loading="lazy"]').length;
  const imagesMissingDimensions = images.filter((_, el) => !$(el).attr('width') || !$(el).attr('height')).length;
  const schemaBlocks = $('script[type="application/ld+json"]').length;
  const hasViewport = $('meta[name="viewport"]').length > 0;
  const findings: AuditFinding[] = [];

  if (!response.ok) {
    findings.push({ category: 'performance', id: 'http-error', severity: 'error', title: 'Non-success HTTP status', detail: `The final response returned HTTP ${response.status}.`, recommendation: 'Resolve the HTTP status before interpreting the rest of the audit.' });
  }

  if (categories.includes('performance')) {
    pushPerformanceFindings(findings, responseMs, htmlBytes, scriptCount, imageCount, lazyImageCount, imagesMissingDimensions, hasViewport);
  }
  if (categories.includes('seo')) {
    pushSeoFindings(findings, title, metaDescription, canonical, lang, h1Count, robots, schemaBlocks);
  }
  if (categories.includes('security')) {
    pushSecurityFindings(findings, response.headers, new URL(response.url));
  }

  const filteredFindings = findings.filter((finding) => categories.includes(finding.category));
  return {
    url: url.toString(),
    finalUrl: response.url,
    status: response.status,
    fetchedAt: new Date().toISOString(),
    timing: { responseMs },
    document: {
      htmlBytes,
      title,
      metaDescription,
      canonical,
      lang,
      h1Count,
      scriptCount,
      stylesheetCount,
      imageCount,
      lazyImageCount,
      imagesMissingDimensions,
      schemaBlocks,
    },
    headers: headerRecord(response.headers),
    findings: filteredFindings,
    summary: {
      errors: filteredFindings.filter((f) => f.severity === 'error').length,
      warnings: filteredFindings.filter((f) => f.severity === 'warning').length,
      info: filteredFindings.filter((f) => f.severity === 'info').length,
    },
  };
}

export function selectCategory(result: AuditResult, category: AuditCategory): AuditResult {
  const findings = result.findings.filter((finding) => finding.category === category);
  return {
    ...result,
    findings,
    summary: {
      errors: findings.filter((f) => f.severity === 'error').length,
      warnings: findings.filter((f) => f.severity === 'warning').length,
      info: findings.filter((f) => f.severity === 'info').length,
    },
  };
}
