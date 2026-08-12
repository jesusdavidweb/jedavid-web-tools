---
name: seo-llm
description: Diagnose and improve technical SEO and discoverability for traditional search engines and LLM-based systems using jedavid-web-tools.
---

# SEO and LLM Discoverability

Use `jedavid-web-tools` to produce a measurable diagnosis of how a public
page is crawled, indexed and understood by both search engines and
LLM-based extractors.

## When to use this skill

- "Audit the SEO of example.com"
- "Can Google index this page?"
- "How is this site optimised for LLMs?"
- "Why is the sitemap not being indexed?"
- "Audit OpenGraph and Twitter Cards"
- "Check our llms.txt"

## Workflow

1. `seo_audit` for a broad technical SEO pass (title, meta description,
   canonical, robots, language, headings, OpenGraph, Twitter Cards,
   hreflang, structured data, images).
2. `seo_indexability` to combine HTTP status, meta robots, X-Robots-Tag,
   canonical and the relevant `robots.txt` rules.
3. `seo_schema` to parse every JSON-LD block, extract `@type` (including
   `@graph`) and surface parse errors.
4. `seo_links` to enumerate internal/external/nofollow and detect generic
   anchor text.
5. `seo_llm` for AI/LLM discoverability: `llms.txt`, robots directives for
   AI crawlers, structured data, semantic metadata.
6. `sitemap_inspect` to confirm the sitemap is reachable, well-formed and
   lists the URLs you expect.
7. `robots_inspect` to confirm robots directives match your crawl policy.

## LLM discoverability — terminology

- **llms.txt**: emerging convention, **not a required standard**. Present
  it as an option, not a mandate.
- **Schema.org (JSON-LD)**: the most reliable signal for LLM-based
  extractors. Add at minimum `Organization`, `WebSite`, and per-page
  types like `Article`, `Product`, `FAQPage`, `BreadcrumbList`.
- **AI crawlers**: GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot,
  Google-Extended, PerplexityBot, Applebot-Extended, Bytespider, CCBot.
  Listing them in `robots.txt` is a **directive**, not a hard block.

## Common findings to escalate

- `seo.canonical.missing` on any indexable page.
- `seo.robots.noindex` or `indexability.noindex.header` on a page that
  should be indexed.
- `indexability.robots.root` (a `Disallow: /` rule).
- `schema.invalid` JSON-LD blocks.
- `llm.llms_txt.missing` is informational only — do not present it as
  failing.

## Safety

Do not recommend cloaking, hidden text, doorway pages or any other
manipulation intended to game ranking or extraction. Recommendations
must align with documented search-engine and LLM-provider guidelines.
