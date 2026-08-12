#!/usr/bin/env node
// bin/jedavid-web-tools-mcp.mjs
// Entry point of the portable MCP runtime.
// Zero npm dependencies — runs from this single repo when imported by an
// Agent Plugins 1.0 client.

import handlers from './lib/handlers.mjs';
import { VERSION, SEVERITY } from './lib/runtime.mjs';

const objectSchema = (properties = {}, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const urlProp = { type: 'string', description: 'Public HTTP(S) URL or hostname.', minLength: 1 };
const repoProp = { type: 'string', pattern: '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', description: 'GitHub repository as owner/name.' };

// Tool definitions. The `annotations` object is mandatory per MCP spec for
// every tool. openWorldHint reflects whether the tool can interact with
// resources outside the host (network, daemon).
const TOOLS = [
  // -- Web / audit ---------------------------------------------------------
  {
    name: 'site_audit',
    title: 'Full website audit',
    description: 'Run a read-only audit across performance, SEO, accessibility, security, indexability, structured data, link profile and stack detection for a public URL. Use this for a first-pass diagnosis before drilling into specific tools.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'http_inspect',
    title: 'HTTP inspection',
    description: 'Inspect the HTTP(S) response for a URL: final status after redirects, response time, headers, content-type, encoding, cache-control and Set-Cookie headers. Use when the question is specifically about transport, not about page content.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'redirect_trace',
    title: 'Trace redirects',
    description: 'Follow the HTTP redirect chain for a URL step by step, returning the status, location and key headers at every hop. Detects redirect loops, HTTP→HTTPS upgrades and long chains. Use when investigating canonicalization, mixed-protocol behaviour or CDN routing.',
    inputSchema: objectSchema({ url: urlProp, max: { type: 'integer', minimum: 1, maximum: 20, default: 10 } }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'page_compare',
    title: 'Compare two pages',
    description: 'Audit two URLs and produce a side-by-side diff of status, response time, document size, script/image counts, title and finding counts. Use for comparing staging vs production, before/after deploys, or for spotting regressions between snapshots.',
    inputSchema: objectSchema({ before: urlProp, after: urlProp }, ['before', 'after']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Performance ---------------------------------------------------------
  {
    name: 'performance_audit',
    title: 'Performance audit',
    description: 'Audit a public URL for performance signals: TTFB, HTML weight, render-blocking scripts, image lazy-loading, viewport, resource hints and compression. Returns only the performance findings from a full site audit.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'performance_assets',
    title: 'Asset inventory',
    description: 'Fetch the initial HTML of a URL, identify same-origin scripts, stylesheets, modules, preloads and images, then issue HEAD requests to record their size, content-type, encoding, cache-control and response time. Use to identify heavy assets and missing cache headers.',
    inputSchema: objectSchema({ url: urlProp, limit: { type: 'integer', minimum: 1, maximum: 50, default: 25 } }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- SEO -----------------------------------------------------------------
  {
    name: 'seo_audit',
    title: 'Technical SEO audit',
    description: 'Audit a public URL for technical SEO signals: title, meta description, canonical, robots, language, heading hierarchy, Open Graph, Twitter Cards, hreflang, structured data, images and pagination. Use for a comprehensive SEO pass before deeper indexability/schema checks.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'seo_indexability',
    title: 'SEO indexability',
    description: 'Determine whether a URL is indexable: HTTP status, meta robots, X-Robots-Tag, canonical, hreflang, and the relevant robots.txt rules. Use when the question is specifically about whether search engines can index the page.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'seo_links',
    title: 'Link analysis',
    description: 'Extract every anchor link from a URL, classify as internal or external, detect nofollow/sponsored/ugc attributes, and report empty-text and generic anchor text. Use for internal-link health, external-link audits and identifying generic link text.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'seo_schema',
    title: 'Structured data',
    description: 'Parse every JSON-LD block on a URL, extract @type(s) including @graph, and report parse errors. Use when verifying structured data for rich results or entity extraction.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'seo_llm',
    title: 'LLM discoverability',
    description: 'Inspect signals that help LLM-based systems discover and ingest a site: llms.txt, robots.txt directives for AI crawlers (GPTBot, ClaudeBot, Google-Extended, PerplexityBot, etc.), JSON-LD structured data, semantic metadata and html[lang]. Note: llms.txt is an emerging convention, not a required standard.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Accessibility -------------------------------------------------------
  {
    name: 'accessibility_audit',
    title: 'Static accessibility audit',
    description: 'Run a static accessibility analysis of a public URL: document language, title, viewport, heading hierarchy, image alt text, form labels, iframe titles, landmarks and skip-navigation indicators. Static analysis cannot prove WCAG compliance — use the findings as triage for manual and assistive-technology testing.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Security ------------------------------------------------------------
  {
    name: 'security_headers',
    title: 'Security headers',
    description: 'Audit HTTP response headers for browser-facing security: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options, COOP/COEP/CORP, plus server version disclosure and X-Powered-By leakage. Use when hardening HTTP transport security.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'security_cookies',
    title: 'Cookie security',
    description: 'Inspect the Set-Cookie headers returned by a URL and report missing Secure, HttpOnly and SameSite attributes. Use when reviewing cookie hygiene.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Stack & crawlability ------------------------------------------------
  {
    name: 'stack_detect',
    title: 'Technology detection',
    description: 'Infer the CDN, framework, CMS, analytics and server technology of a URL from HTML and HTTP response headers (e.g. WordPress, WooCommerce, Next.js, Astro, SvelteKit, Vue, Nuxt, Cloudflare, Vercel, Netlify, Fastly, Akamai, Google Analytics, GTM, Meta Pixel). Each detection includes evidence and confidence.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'robots_inspect',
    title: 'robots.txt inspection',
    description: 'Fetch /robots.txt for a URL, parse user-agents, disallow/allow rules and sitemap declarations. Use for crawlability audits.',
    inputSchema: objectSchema({ url: urlProp }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'sitemap_inspect',
    title: 'Sitemap inspection',
    description: 'Fetch /sitemap.xml (or sitemap index) for a URL, classify the document type, count entries and return up to N URLs. Use for crawl coverage and sitemap hygiene.',
    inputSchema: objectSchema({ url: urlProp, limit: { type: 'integer', minimum: 1, maximum: 500, default: 100 } }, ['url']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Cloudflare ----------------------------------------------------------
  {
    name: 'cloudflare_account',
    title: 'Cloudflare account',
    description: 'Read Cloudflare account metadata for the configured CLOUDFLARE_ACCOUNT_ID. Requires CLOUDFLARE_API_TOKEN.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_zones',
    title: 'Cloudflare zones',
    description: 'List up to 50 Cloudflare zones visible to the configured CLOUDFLARE_API_TOKEN. Requires CLOUDFLARE_API_TOKEN.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_zone',
    title: 'Cloudflare zone',
    description: 'Read Cloudflare zone metadata for a domain (status, plan, name servers). Requires CLOUDFLARE_API_TOKEN.',
    inputSchema: objectSchema({ domain: { type: 'string', minLength: 1 } }, ['domain']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_dns',
    title: 'Cloudflare DNS records',
    description: 'List DNS records for a Cloudflare zone, optionally filtered by record type. Requires CLOUDFLARE_API_TOKEN.',
    inputSchema: objectSchema({ domain: { type: 'string', minLength: 1 }, type: { type: 'string', description: 'Optional record type filter (A, AAAA, CNAME, MX, TXT, ...).' } }, ['domain']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_workers',
    title: 'Cloudflare Workers',
    description: 'List Cloudflare Worker scripts in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_pages',
    title: 'Cloudflare Pages projects',
    description: 'List Cloudflare Pages projects in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_d1',
    title: 'Cloudflare D1 databases',
    description: 'List D1 databases in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_r2',
    title: 'Cloudflare R2 buckets',
    description: 'List R2 buckets in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_kv',
    title: 'Cloudflare KV namespaces',
    description: 'List KV namespaces in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_queues',
    title: 'Cloudflare Queues',
    description: 'List Cloudflare Queues in the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'cloudflare_access',
    title: 'Cloudflare Access apps',
    description: 'List Cloudflare Access applications for the configured account. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- GitHub --------------------------------------------------------------
  {
    name: 'github_repo',
    title: 'GitHub repository',
    description: 'Read public metadata for a GitHub repository (description, default branch, visibility, license, open issues, stars, forks, topics, dates). Optional GITHUB_TOKEN for private repos and higher rate limits.',
    inputSchema: objectSchema({ repo: repoProp }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_branches',
    title: 'GitHub branches',
    description: 'List branches of a GitHub repository with their protected flag and head SHA. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, limit: { type: 'integer', minimum: 1, maximum: 100, default: 30 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_pull_requests',
    title: 'GitHub pull requests',
    description: 'List pull requests for a GitHub repository by state (open/closed/all). Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, state: { type: 'string', enum: ['open', 'closed', 'all'], default: 'open' }, limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_issues',
    title: 'GitHub issues',
    description: 'List issues (excluding pull requests) for a GitHub repository. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, state: { type: 'string', enum: ['open', 'closed', 'all'], default: 'open' }, limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_releases',
    title: 'GitHub releases',
    description: 'List GitHub releases for a repository. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, limit: { type: 'integer', minimum: 1, maximum: 50, default: 10 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_actions',
    title: 'GitHub Actions runs',
    description: 'List recent GitHub Actions workflow runs for a repository. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, limit: { type: 'integer', minimum: 1, maximum: 30, default: 10 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_workflow_runs',
    title: 'GitHub workflow runs',
    description: 'List workflow runs for a specific workflow file (or all workflows) in a repository. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, workflow: { type: 'string', description: 'Optional workflow file name, e.g. "ci.yml".' }, limit: { type: 'integer', minimum: 1, maximum: 50, default: 20 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'github_deployments',
    title: 'GitHub deployments',
    description: 'List recent deployments for a GitHub repository. Optional GITHUB_TOKEN.',
    inputSchema: objectSchema({ repo: repoProp, limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }, ['repo']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- WordPress -----------------------------------------------------------
  {
    name: 'wordpress_rest_index',
    title: 'WordPress REST index',
    description: 'Inspect the configured WordPress REST API root: namespaces, routes, name and description. Use to confirm the WP REST API is reachable and to discover which namespaces are exposed (e.g. wp/v2, wc/v3, custom plugins).',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'wordpress_plugins',
    title: 'WordPress plugins',
    description: 'List installed WordPress plugins with status, version and author. Requires WORDPRESS_USERNAME and WORDPRESS_APP_PASSWORD with plugin-listing capability.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'wordpress_themes',
    title: 'WordPress themes',
    description: 'List installed WordPress themes with status, version and author. Requires WORDPRESS_USERNAME and WORDPRESS_APP_PASSWORD with theme-listing capability.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'wordpress_users',
    title: 'WordPress users',
    description: 'List WordPress users with roles. Requires WORDPRESS_USERNAME and WORDPRESS_APP_PASSWORD with user-listing capability. Returns identifying information; treat as sensitive.',
    inputSchema: objectSchema({ limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- WooCommerce ---------------------------------------------------------
  {
    name: 'woocommerce_system_status',
    title: 'WooCommerce system status',
    description: 'Read WooCommerce system status (environment, database, active plugins, theme and core settings). Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'woocommerce_webhooks',
    title: 'WooCommerce webhooks',
    description: 'List WooCommerce webhooks (id, name, status, topic, delivery URL). Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET.',
    inputSchema: objectSchema({ limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'woocommerce_orders',
    title: 'WooCommerce orders',
    description: 'List recent WooCommerce orders (id, number, status, total, customer email, date). Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET with read orders capability.',
    inputSchema: objectSchema({ status: { type: 'string', default: 'any' }, limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'woocommerce_products',
    title: 'WooCommerce products',
    description: 'List WooCommerce products (id, name, slug, status, type, SKU, price, stock status, stock quantity, total sales). Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET.',
    inputSchema: objectSchema({ limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 } }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'woocommerce_gateways',
    title: 'WooCommerce payment gateways',
    description: 'List WooCommerce payment gateways (id, title, enabled, method title/description). Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'woocommerce_shipping',
    title: 'WooCommerce shipping zones',
    description: 'List WooCommerce shipping zones and the methods configured within each. Requires WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  // -- Docker --------------------------------------------------------------
  {
    name: 'docker_ps',
    title: 'Docker containers',
    description: 'List local Docker containers (running and stopped) with status, image, ports and creation date. Requires the Docker CLI and access to the daemon. Read-only.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_inspect',
    title: 'Docker inspect',
    description: 'Read docker inspect data for one local container, with secret-looking environment values redacted. Requires the Docker CLI.',
    inputSchema: objectSchema({ container: { type: 'string', pattern: '^[A-Za-z0-9_.-]+$', minLength: 1 } }, ['container']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_logs',
    title: 'Docker logs',
    description: 'Read a bounded tail of local container logs (max 500 lines). Treat the output as potentially sensitive and summarize only what is needed.',
    inputSchema: objectSchema({ container: { type: 'string', pattern: '^[A-Za-z0-9_.-]+$', minLength: 1 }, lines: { type: 'integer', minimum: 1, maximum: 500, default: 100 } }, ['container']),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_stats',
    title: 'Docker stats',
    description: 'Read a one-shot snapshot of CPU, memory, network and block I/O for every running container. Requires the Docker CLI.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_images',
    title: 'Docker images',
    description: 'List local Docker images with tags, sizes and creation date. Requires the Docker CLI.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_networks',
    title: 'Docker networks',
    description: 'List local Docker networks with driver and scope. Requires the Docker CLI.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_volumes',
    title: 'Docker volumes',
    description: 'List local Docker volumes with driver, scope and mountpoint. Requires the Docker CLI.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'docker_compose_status',
    title: 'Docker Compose status',
    description: 'Read docker compose ps for the current working directory (or a project context if configured). Requires the Docker CLI and a compose project.',
    inputSchema: objectSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

// MCP protocol handlers
// ---------------------

const SERVER_INFO = { name: 'jedavid-web-tools', version: VERSION };
const INSTRUCTIONS = [
  'Read-only web engineering diagnostics. The toolkit is safe by default: public URL tools block localhost and private network targets to reduce SSRF risk.',
  'Start with site_audit for a broad baseline, then drill into performance_audit, seo_audit, accessibility_audit, security_headers or stack_detect.',
  'Cloudflare, GitHub, WordPress/WooCommerce and Docker integrations are read-only and use environment variables for credentials. Do not pass secrets as tool arguments.',
  'Treat every diagnostic as a hypothesis to validate, not as permission to mutate a site, DNS, deployment, container or CMS.',
].join(' ');

function serverDiscover() {
  return {
    resultType: 'complete',
    supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
    capabilities: { tools: { listChanged: false } },
    serverInfo: SERVER_INFO,
    instructions: INSTRUCTIONS,
  };
}

function serverInitialize(msg) {
  const requested = msg.params?.protocolVersion;
  const supported = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
  return {
    protocolVersion: supported.includes(requested) ? requested : '2025-11-25',
    capabilities: { tools: { listChanged: false } },
    serverInfo: SERVER_INFO,
    instructions: INSTRUCTIONS,
  };
}

function toolsList() {
  return { tools: TOOLS };
}

async function toolsCall(msg) {
  const name = msg.params?.name;
  const args = msg.params?.arguments || {};
  const fn = handlers[name];
  if (!fn) {
    const err = new Error(`Unknown tool: ${name}`);
    err.code = -32602;
    throw err;
  }
  return await fn(args);
}

function dispatch(msg) {
  const method = msg.method;
  if (method === 'server/discover') return Promise.resolve(serverDiscover());
  if (method === 'initialize') return Promise.resolve(serverInitialize(msg));
  if (method === 'ping') return Promise.resolve({});
  if (method === 'tools/list') return Promise.resolve(toolsList());
  if (method === 'tools/call') return toolsCall(msg);
  if (typeof method === 'string' && method.startsWith('notifications/')) return Promise.resolve(null);
  return Promise.reject(Object.assign(new Error(`Method not found: ${method}`), { code: -32601 }));
}

function textResult(value) {
  if (value && value.content && Array.isArray(value.content)) {
    // The handler already produced MCP-shaped content (e.g. soft error).
    return value;
  }
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], structuredContent: value };
}

function errResult(err) {
  const message = err && err.message ? err.message : String(err);
  return { isError: true, content: [{ type: 'text', text: message }] };
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (line) handleLine(line);
  }
});

async function handleLine(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (!('id' in msg)) return; // ignore notifications
  try {
    const result = await dispatch(msg);
    if (result === null) return; // notification ack
    const payload = msg.method === 'tools/call' ? textResult(result) : result;
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: payload }) + '\n');
  } catch (e) {
    if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: errResult(e) }) + '\n');
      return;
    }
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: e.code || -32603, message: e.message || String(e) } }) + '\n');
  }
}

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
