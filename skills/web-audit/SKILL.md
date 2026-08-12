---
name: web-audit
description: Audit public websites using jedavid-web-tools for performance, SEO, accessibility, security, indexability, structured data, LLM discoverability and technology detection.
---

# Web Audit

Use the `jedavid-web-tools` MCP server as the measurement layer. Prefer tool output over assumptions.

## Default workflow

1. Start with `site_audit` for a broad baseline.
2. Use `stack_detect` to understand the delivery/framework context.
3. Drill into the relevant domain with `performance_audit`, `seo_audit`, `accessibility_audit`, or `security_headers`.
4. Use specialized tools (`performance_assets`, `seo_schema`, `seo_links`, `seo_indexability`, `seo_llm`, `robots_inspect`, `sitemap_inspect`) to identify root causes.
5. If comparing a deployed change, use `page_compare`.
6. Distinguish measured facts from inferred causes.

## Priorities

For performance, prioritize user-impacting causes over scores: response latency, render-critical weight, excessive scripts, image behavior, caching and layout stability. For SEO, prioritize indexability, canonicals, content semantics, structured data and crawlability. For security, do not recommend blindly enabling a policy without considering compatibility.

## Safety

All plugin tools are read-only. Do not interpret diagnostics as authorization to edit repositories, DNS, deployments, containers, WordPress or WooCommerce. Public URL tools block localhost and private-network targets to reduce SSRF risk.
