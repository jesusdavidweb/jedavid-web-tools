---
name: security-review
description: Defensive security review of public HTTP responses and configured integrations using jedavid-web-tools.
---

# Security Review

Use `jedavid-web-tools` for **defensive** security review of public HTTP
responses and the surface of configured integrations. The toolkit is
strictly read-only: it must not be used to probe, attack or modify any
system you do not own or have explicit permission to test.

## When to use this skill

- "Audit the security headers of example.com"
- "Check whether the cookies are safe"
- "Is the site vulnerable to clickjacking?"
- "Review the WordPress / WooCommerce / Cloudflare configuration"
- "Compare staging and production for security regressions"

## Workflow

1. `http_inspect` for the raw response, including status, headers and
   cookies.
2. `security_headers` for the full set of browser-facing security
   headers. The findings will flag:
   - `content-security-policy` missing (medium)
   - `strict-transport-security` missing on HTTPS (medium)
   - `x-content-type-options` missing (medium)
   - `referrer-policy` missing (low)
   - `permissions-policy` missing (low)
   - `x-frame-options` missing (low)
   - `cross-origin-opener-policy`, `cross-origin-embedder-policy`,
     `cross-origin-resource-policy` (info / low)
   - Server version disclosure (`server: nginx/1.x.y`)
   - `x-powered-by` disclosure
3. `security_cookies` for Set-Cookie attributes: `Secure`, `HttpOnly`,
   `SameSite`, plus `Path` and `Domain` observations.
4. `seo_indexability` to confirm the page is not accidentally marked
   `noindex` and that the canonical is consistent.
5. For platform integrations, drill down:
   - **Cloudflare**: `cloudflare_zone` → `cloudflare_dns`. Confirm
     registrar lock, DNSSEC if exposed, nameservers, and that
     `proxied: true` is intentional.
   - **GitHub**: `github_repo` for visibility, default branch, license
     and topics; `github_actions` for run history.
   - **WordPress / WooCommerce**: `wordpress_rest_index`,
     `wordpress_plugins`, `woocommerce_system_status`. Surface outdated
     plugins/themes and weak system indicators.
   - **Docker**: `docker_ps` → `docker_inspect` (one container). The
     inspect handler redacts secret-looking env vars automatically.

## Severity scale for security findings

- `critical` — actively dangerous (e.g. unauthenticated admin endpoint).
- `high` — likely exploitable under common conditions (e.g. no HSTS on
  HTTPS, page marked noindex by mistake exposing it in dev).
- `medium` — should fix (CSP missing, X-Content-Type-Options missing,
  cookies without `Secure`/`HttpOnly`/`SameSite`).
- `low` — defence in depth (Referrer-Policy, Permissions-Policy, COOP).
- `info` — observation (server header, COEP).

## Safety

- The toolkit is defensive only. It must not be used for offensive
  scanning, fuzzing or exploitation.
- `security_cookies` inspects cookies set by the URL in scope. Do not
  point it at third-party domains you do not own.
- For password, secret, API-key or token material: never paste it into
  the chat. Configure integrations in the MCP runtime environment.
- When a tool returns an authentication or permission error, the error
  message includes the required scope when the upstream API tells us.
  Use that to request the right token, not the broadest possible one.
