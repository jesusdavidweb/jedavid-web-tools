---
name: web-audit
description: Audit public websites using jedavid-web-tools for performance, SEO, accessibility, security, indexability, structured data, LLM discoverability and technology detection.
---

# Web Audit

Use the `jedavid-web-tools` MCP server as the measurement layer. Prefer tool output over assumptions.

## Default workflow

1. Start with `site_audit` for a broad baseline. The result already includes
   a `summary` (severity + category counts), a flat `findings` array and
   evidence collected for the same page.
2. Use `stack_detect` to understand the delivery and framework context —
   CDN, framework, CMS, analytics. This shapes every later recommendation.
3. Drill into the relevant domain with the category-specific tools:
   - `performance_audit` for TTFB, HTML weight, render-blocking, images.
   - `seo_audit` for title, description, canonical, headings, OG, Twitter.
   - `accessibility_audit` for lang, alt, labels, headings, landmarks.
   - `security_headers` for CSP, HSTS, COOP/COEP/CORP, server disclosure.
4. Use specialized tools to identify root causes:
   - `performance_assets` to find heavy same-origin assets and missing cache headers.
   - `seo_indexability` to combine HTTP status, robots meta, X-Robots-Tag,
     canonical and robots.txt into one indexability verdict.
   - `seo_schema` to validate JSON-LD blocks and extract @type(s) (including @graph).
   - `seo_links` to enumerate internal/external/nofollow and detect generic
     anchor text.
   - `seo_llm` to inspect llms.txt, robots directives for AI crawlers, structured
     data and semantic metadata.
   - `seo_indexability` to check HTTP status, canonical, robots and robots.txt
     for indexability risk.
   - `redirect_trace` to follow the redirect chain explicitly and detect loops
     or HTTP→HTTPS upgrades.
   - `robots_inspect` and `sitemap_inspect` for crawlability.
5. If comparing a deployed change, use `page_compare` (before/after URLs).
6. Distinguish measured facts from inferred causes in your final report.

## Result envelope

Every tool returns the same shape:

```json
{
  "ok": true,
  "tool": "site_audit",
  "target": "https://example.com/",
  "summary": { "bySeverity": { "high": 3 }, "byCategory": { "security": 4 } },
  "findings": [
    { "id": "security.headers.csp.missing", "severity": "medium", "category": "security", "title": "...", "description": "...", "recommendation": "..." }
  ],
  "evidence": [{ "type": "http", "summary": "HTTP 200 in 124 ms" }],
  "metadata": { "version": "0.3.0", "fetchedAt": "2026-08-12T..." },
  "data": { /* tool-specific payload */ }
}
```

Use `summary` for the headline, `findings` for actionable items and `evidence`
to back your claims.

## Severity scale

- `critical` — actively breaks or compromises the page.
- `high` — must-fix: missing H1, missing viewport, server version disclosure.
- `medium` — should-fix: missing CSP, noindex accidental, no alt.
- `low` — nice-to-fix: missing COOP, generic anchor text.
- `info` — observation: missing JSON-LD on a non-product page.

## Safety

- All public-URL tools are read-only and block localhost, private IPs
  (including CGNAT 100.64.0.0/10, link-local 169.254.0.0/16) and metadata
  endpoints via DNS resolution at every redirect hop.
- Diagnostic output is not permission to mutate a site. Do not interpret
  findings as authorization to edit DNS, deploys, WordPress, WooCommerce
  or containers.
