---
name: performance-optimization
description: Diagnose and prioritize web performance issues using jedavid-web-tools: TTFB, HTML weight, render-blocking scripts, images, caching, and same-origin assets.
---

# Performance Optimization

Use `jedavid-web-tools` to produce a measured, prioritized diagnosis of
front-end performance. The toolkit intentionally avoids shipping a
browser — these heuristics are not a replacement for real-user monitoring
or lab data from PageSpeed Insights / CrUX, but they reliably identify
the most common regressions.

## When to use this skill

- "Is the page slow?"
- "Audit the front-end performance of example.com"
- "Find heavy assets"
- "Why is the LCP image not loading?"
- "Compare performance before and after a deploy"

## Workflow

1. `site_audit` for a baseline. The performance findings will surface the
   most impactful issues:
   - `perf.ttfb.slow` (TTFB > 1s, severity scales with duration)
   - `perf.html.large` (HTML > 200 KiB, severity scales with size)
   - `perf.scripts.render_blocking`
   - `perf.images.all_lazy` (every image lazy-loaded, LCP risk)
   - `perf.images.cls` (images without explicit dimensions)
   - `perf.viewport.missing` (no responsive viewport)
   - `perf.compression.missing` (no `content-encoding`)
   - `perf.preload.missing` and `perf.preconnect.missing`
2. `performance_audit` for the focused subset.
3. `performance_assets` to inspect same-origin scripts, stylesheets and
   images. Each entry reports `contentLength`, `contentType`,
   `contentEncoding`, `cacheControl` and `responseMs`. The handler flags
   large assets and missing `Cache-Control`.
4. `page_compare` to compare two URLs (e.g. staging vs production, or
   before/after a deploy).
5. `http_inspect` for the raw response, including redirect chain and
   final cache-control header.

## Prioritization

Always rank by user impact, not by score:

1. **TTFB** — a slow first byte breaks everything else.
2. **HTML weight** — fewer than 100 KiB is a reasonable budget; > 500 KiB
   is a regression worth investigating.
3. **Render-blocking scripts** in the head without `async` or `defer`.
4. **Above-the-fold images** without `width`/`height` (CLS) or with
   `loading="lazy"` (LCP delay).
5. **Missing compression** (`content-encoding`) on text responses.
6. **Missing resource hints** (`rel="preload"` for the LCP image or
   critical fonts, `rel="preconnect"` for required third-party origins).
7. **Heavy assets** identified by `performance_assets` and missing
   long-lived `Cache-Control`.

## Adapters (future, optional)

External lab data (PageSpeed Insights, CrUX) is not bundled. The Core
exposes types that adapters can plug into without changing tool shapes.

## Safety

Performance recommendations should not break the page:

- Never lazy-load the LCP image.
- Never remove `width`/`height` while switching to a new layout.
- Be careful with `defer` and `async` on scripts that depend on parse
  order or that write to `document.head` synchronously.
