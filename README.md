# jedavid-web-tools

> **Portable, read-only web engineering toolkit for AI agents.**
> Performance, SEO, accessibility, security, indexability, structured data,
> LLM discoverability, WordPress, WooCommerce, Cloudflare, GitHub and Docker
> diagnostics — over the Model Context Protocol.

`jedavid-web-tools` is designed to be imported as an [Agent Plugin 1.0] in
any MCP-capable client (MiniMax, Claude, ChatGPT, Codex, OpenCode, etc.).
The same repository doubles as a CLI and as a TypeScript library for
custom integrations.

[Agent Plugin 1.0]: https://agent-plugins.org

---

## Why

Auditing, debugging and operating a website is a multi-tool job. The
toolkit is built around three principles:

1. **Composable, not monolithic.** A `site_audit` is a high-level
   orchestrator, but every signal it produces is also available as a
   single, focused tool. Skills and agents can mix and match.
2. **Portable by default.** The runtime in `bin/` is a single
   dependency-free Node.js script. A client can import the GitHub
   repository and start the MCP server with no `pnpm install` step.
3. **Defensive and read-only.** Public-URL tools block SSRF targets
   (localhost, private ranges, metadata endpoints) at every redirect hop.
   Cloudflare, GitHub, WordPress, WooCommerce and Docker tools perform
   inspection only — never mutation.

---

## Architecture

```
Agent
  ↓
Skills (web-audit, platform-ops, wordpress-commerce, seo-llm,
        performance-optimization, security-review)
  ↓
MCP tools (54 small primitives over the portable runtime)
  ↓
Core (typed library: SSRF, HTTP, HTML, findings generators)
  ↓
Adapters / Providers
  ↓
HTTP / DNS / Cloudflare API / GitHub API / WP REST / WC REST / Docker CLI
```

- **Skills** are knowledge and strategy. They tell the agent which tool to
  call, in which order, and how to interpret the result.
- **MCP tools** are small, deterministic primitives. They never try to do
  everything at once.
- **The Core** is the analysis layer (TypeScript + cheerio for development,
  dependency-free JS for the portable runtime).
- **Adapters** encapsulate external services. None of them accept
  credentials as tool arguments — they read the MCP runtime environment.

---

## Repository layout

```text
.
├── bin/                                # Portable runtime (zero npm deps)
│   ├── jedavid-web-tools-mcp.mjs       # MCP server entry point
│   └── lib/                            # runtime, html, handlers
├── packages/
│   ├── core/                           # Typed analysis library (cheerio)
│   ├── cli/                            # `jedavid-web-tools` CLI
│   └── mcp/                            # Development MCP server (uses SDK)
├── skills/                             # Agent Plugins 1.0 skills
│   ├── web-audit/
│   ├── platform-ops/
│   ├── wordpress-commerce/
│   ├── seo-llm/
│   ├── performance-optimization/
│   └── security-review/
├── tests/                              # node:test unit + integration suite
│   ├── runtime.test.mjs                # SSRF, helpers, result envelope
│   ├── html.test.mjs                   # page model, findings generators
│   ├── core.test.mjs                   # Core TypeScript
│   ├── mcp.test.mjs                    # MCP protocol (init, list, call, errors)
│   └── integration.test.mjs            # End-to-end against a local fixture server
├── plugin.json                         # Agent Plugins 1.0 manifest
├── mcp.json                            # MCP server manifest
├── package.json                        # Monorepo root (pnpm workspaces)
├── pnpm-workspace.yaml
├── tsconfig.base.json
└── .github/workflows/ci.yml
```

The portable MCP runtime in `bin/` is intentionally separated from the
TypeScript packages: it is what an Agent Plugin client imports. The
TypeScript packages remain the development surface (typed API, IDE
tooling, dev-time MCP server, CLI).

---

## Quick start

### As an Agent Plugin

In any Agent Plugins 1.0 client, import:

```text
https://github.com/jesusdavidweb/jedavid-web-tools
```

A conforming client should discover **6 skills** and **1 MCP server**
with **54 tools**. The MCP server is launched directly by the client
with `node bin/jedavid-web-tools-mcp.mjs`; no `pnpm install` is required.

### As a CLI

```bash
corepack enable
pnpm install
pnpm build
pnpm audit https://example.com --category=performance,seo
```

### As a portable MCP server

```bash
node bin/jedavid-web-tools-mcp.mjs
```

List the tools it advertises:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | node bin/jedavid-web-tools-mcp.mjs
```

---

## Tools (54)

| Tool | Category | Auth | Read-only | Description |
| --- | --- | --- | --- | --- |
| `site_audit` | web | – | yes | Broad baseline: performance, SEO, accessibility, security, stack |
| `http_inspect` | web | – | yes | HTTP status, headers, content-type, encoding, cache-control, cookies |
| `redirect_trace` | web | – | yes | Follow redirects hop-by-hop, detect loops and HTTP→HTTPS upgrades |
| `page_compare` | web | – | yes | Side-by-side diff of two URLs |
| `performance_audit` | web | – | yes | Performance-focused subset of `site_audit` |
| `performance_assets` | web | – | yes | Same-origin scripts, stylesheets, images with size and cache headers |
| `seo_audit` | web | – | yes | Title, description, canonical, headings, OG, Twitter, hreflang, structured data |
| `seo_indexability` | web | – | yes | Indexability verdict combining HTTP status, robots, canonical and robots.txt |
| `seo_links` | web | – | yes | Internal/external/nofollow classification, empty-text and generic anchors |
| `seo_schema` | web | – | yes | Parse JSON-LD blocks, extract @type (including @graph), surface parse errors |
| `seo_llm` | web | – | yes | llms.txt, AI crawler directives, structured data, semantic metadata |
| `accessibility_audit` | web | – | yes | Static accessibility signals (lang, alt, labels, headings, landmarks, skip-link) |
| `security_headers` | web | – | yes | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, COOP/COEP/CORP, X-Frame-Options |
| `security_cookies` | web | – | yes | Set-Cookie attribute analysis (Secure, HttpOnly, SameSite) |
| `stack_detect` | web | – | yes | CDN, framework, CMS, analytics, server inference with evidence and confidence |
| `robots_inspect` | web | – | yes | robots.txt parser (user-agents, disallow, allow, sitemaps) |
| `sitemap_inspect` | web | – | yes | /sitemap.xml parser, urlset/index classification |
| `cloudflare_account` | cloudflare | token | yes | Account metadata |
| `cloudflare_zones` | cloudflare | token | yes | List zones visible to the token |
| `cloudflare_zone` | cloudflare | token | yes | Single zone metadata |
| `cloudflare_dns` | cloudflare | token | yes | DNS records for a zone (optionally filtered by type) |
| `cloudflare_workers` | cloudflare | token + account | yes | Worker scripts in an account |
| `cloudflare_pages` | cloudflare | token + account | yes | Cloudflare Pages projects |
| `cloudflare_d1` | cloudflare | token + account | yes | D1 databases |
| `cloudflare_r2` | cloudflare | token + account | yes | R2 buckets |
| `cloudflare_kv` | cloudflare | token + account | yes | KV namespaces |
| `cloudflare_queues` | cloudflare | token + account | yes | Queues |
| `cloudflare_access` | cloudflare | token + account | yes | Access applications |
| `github_repo` | github | optional token | yes | Repository metadata |
| `github_branches` | github | optional token | yes | Branches and protection |
| `github_pull_requests` | github | optional token | yes | PRs by state |
| `github_issues` | github | optional token | yes | Issues (excluding PRs) |
| `github_releases` | github | optional token | yes | Releases |
| `github_actions` | github | optional token | yes | Workflow runs |
| `github_workflow_runs` | github | optional token | yes | Runs for a specific workflow |
| `github_deployments` | github | optional token | yes | Deployments |
| `wordpress_rest_index` | wordpress | basic auth | yes | REST API namespaces and routes |
| `wordpress_plugins` | wordpress | basic auth | yes | Installed plugins with status and version |
| `wordpress_themes` | wordpress | basic auth | yes | Installed themes with status and version |
| `wordpress_users` | wordpress | basic auth | yes | Users (treat as sensitive) |
| `woocommerce_system_status` | woocommerce | wc keys | yes | System status (environment, theme, active plugins) |
| `woocommerce_webhooks` | woocommerce | wc keys | yes | Webhook configuration |
| `woocommerce_orders` | woocommerce | wc keys | yes | Recent orders summary |
| `woocommerce_products` | woocommerce | wc keys | yes | Products summary |
| `woocommerce_gateways` | woocommerce | wc keys | yes | Payment gateways |
| `woocommerce_shipping` | woocommerce | wc keys | yes | Shipping zones and methods |
| `docker_ps` | docker | local CLI | yes | Local containers |
| `docker_inspect` | docker | local CLI | yes | Container inspect (secrets redacted) |
| `docker_logs` | docker | local CLI | yes | Bounded tail of logs (max 500 lines) |
| `docker_stats` | docker | local CLI | yes | One-shot CPU/memory/IO snapshot |
| `docker_images` | docker | local CLI | yes | Local images |
| `docker_networks` | docker | local CLI | yes | Local networks |
| `docker_volumes` | docker | local CLI | yes | Local volumes |
| `docker_compose_status` | docker | local CLI | yes | `docker compose ps` for the current project |

Every tool advertises the standard MCP `annotations`:

- `readOnlyHint: true` (the toolkit is read-only by design).
- `destructiveHint: false`.
- `idempotentHint: true`.
- `openWorldHint`: `true` for network tools, `false` for local Docker tools.

Future write tools (Cloudflare DNS, GitHub issue creation, WordPress
maintenance, deployment actions) will be introduced under their own
namespace with `destructiveHint: true`, allowlists and confirmation
flows. They are not part of the default toolkit.

---

## Environment variables

| Variable | Used by | Notes |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | Cloudflare tools | A least-privilege read token. |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account-scoped tools | Required for Workers, Pages, D1, R2, KV, Queues, Access. |
| `GITHUB_TOKEN` | GitHub tools | Optional for public repos. Required for private and rate-limited access. |
| `WORDPRESS_BASE_URL` | WordPress tools | Must be HTTPS. |
| `WORDPRESS_USERNAME` | WordPress plugin/theme/user tools | Application-Password-capable user. |
| `WORDPRESS_APP_PASSWORD` | WordPress plugin/theme/user tools | An Application Password, not the login password. |
| `WOOCOMMERCE_BASE_URL` | WooCommerce tools | Must be HTTPS. |
| `WOOCOMMERCE_KEY` | WooCommerce tools | Consumer key (preferably read-only). |
| `WOOCOMMERCE_SECRET` | WooCommerce tools | Consumer secret. |

Credentials are **never** accepted as MCP tool arguments. They belong in
the MCP runtime environment.

---

## Result envelope

Every tool returns the same shape so that agents can combine findings
across tools predictably.

```json
{
  "ok": true,
  "tool": "site_audit",
  "target": "https://example.com/",
  "summary": {
    "total": 12,
    "bySeverity": { "info": 5, "low": 4, "medium": 3, "high": 0, "critical": 0 },
    "byCategory": { "seo": 4, "performance": 3, "security": 5 }
  },
  "findings": [
    {
      "id": "seo.canonical.missing",
      "severity": "low",
      "category": "seo",
      "title": "Missing canonical",
      "description": "No <link rel=\"canonical\"> was found.",
      "recommendation": "Add a self-referencing or intentionally consolidated canonical URL."
    }
  ],
  "evidence": [
    { "type": "http", "summary": "HTTP 200 in 124 ms" },
    { "type": "html", "summary": "12.4 KiB HTML" }
  ],
  "metadata": {
    "fetchedAt": "2026-08-12T11:24:00.000Z",
    "durationMs": 124,
    "version": "0.3.0"
  },
  "data": { /* tool-specific payload */ }
}
```

- `summary` is the headline: severity and category counts.
- `findings` is the actionable list. Each finding has `id`, `severity`,
  `category`, `title`, `description`, optional `evidence` and
  `recommendation`.
- `evidence` is the raw data that supports the findings (HTTP response,
  HTML sample, headers, …).
- `data` is the tool-specific payload.
- `metadata` carries the version, timestamp and tool duration.

### Severity scale

- `info` — observation, no action required.
- `low` — nice-to-fix.
- `medium` — should-fix.
- `high` — must-fix.
- `critical` — actively breaks or compromises the page.

---

## Skills

The toolkit ships six skills. Each skill is a markdown file that
describes **when** to use which tool, in **what order**, and how to
interpret the result. Skills do not duplicate implementation; they
describe strategy.

- **`web-audit`** — broad website audit. Start with `site_audit`,
  narrow with `performance_audit`, `seo_audit`, `accessibility_audit`,
  `security_headers`, then `stack_detect`, then root-cause tools.
- **`platform-ops`** — Cloudflare, GitHub and Docker inspection.
  All read-only. Use the smallest tool that answers the question.
- **`wordpress-commerce`** — WordPress and WooCommerce via REST.
  Uses environment credentials, never tool arguments.
- **`seo-llm`** — technical SEO + LLM discoverability. Treats
  `llms.txt` as an emerging convention, not a standard.
- **`performance-optimization`** — TTFB, HTML weight, render-blocking,
  images, caching, resource hints.
- **`security-review`** — defensive security review. Browser-facing
  headers, cookies, integration configuration.

---

## Examples

### "Audit example.com completely"

```text
1. site_audit          https://example.com
2. stack_detect        https://example.com
3. seo_indexability    https://example.com
4. security_headers    https://example.com
5. accessibility_audit https://example.com
6. performance_assets  https://example.com
7. correlate findings
8. prioritise by severity and user impact
```

### "Is Google able to index this page?"

```text
seo_indexability https://example.com
  → finalUrl, status, robots meta, X-Robots-Tag, canonical, robots.txt
```

### "What is the server stack?"

```text
stack_detect https://example.com
  → CDN, framework, CMS, analytics, server
```

### "Are my Cloudflare zones reachable?"

```text
cloudflare_account
cloudflare_zones
cloudflare_zone example.com
cloudflare_dns example.com
```

### "Compare staging and production"

```text
page_compare
  before: https://staging.example.com/
  after:  https://www.example.com/
```

---

## Security model

The portable plugin is **read-only** by design.

- **SSRF defense.** Public-URL fetchers refuse `localhost`, the
  `*.local` and `*.localhost` zones, the IPv4 ranges
  `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (including
  `169.254.169.254` for cloud metadata), `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10` (CGNAT), `192.0.0.0/24`,
  `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`,
  `203.0.113.0/24`, multicast `224.0.0.0/4`, `240.0.0.0/4` and the
  broadcast address. IPv6 fetches reject `::1`, `::`, `fc00::/7`,
  `fe80::/10`, `ff00::/8`, `2001:db8::/32`, IPv4-mapped and 6to4
  addresses that resolve to a private IPv4 octet. Every redirect hop is
  re-validated against the same policy.
- **Hard size cap.** Any fetched body is rejected above 2.5 MiB.
- **Bounded concurrency and timeouts.** Every HTTP request has a
  per-request timeout (default 15 s) and the redirect loop is bounded.
- **Credentials.** Integrations read credentials from the MCP runtime
  environment. Tool arguments never carry secrets.
- **No shell on user input.** Docker handlers use `execFile` with
  argument allowlists (container names match `^[A-Za-z0-9_.-]+$`).
  There is intentionally no `execute_command` tool.

When a test-only loopback opt-in is required, the runtime honours the
`JEDAVID_TEST_ALLOW_LOOPBACK=1` env var. In normal operation this env
var is unset and loopback targets are still blocked.

---

## MCP compatibility

- Modern: `server/discover` advertises support for protocol
  `2026-07-28`, `2025-11-25` and `2025-06-18`.
- Legacy: `initialize` negotiates the highest mutually supported
  protocol among `2025-11-25`, `2025-06-18`, `2025-03-26`,
  `2024-11-05`.
- Stdio: newline-delimited JSON-RPC.
- Tools: `tools/list` advertises 54 tools with full schemas and
  annotations. `tools/call` wraps the handler result in a
  `content` + `structuredContent` envelope per the MCP spec.
- Errors: tools return a JSON-RPC `error` with code `-32601` for
  unknown methods and a `tools/call` `isError: true` content array
  for handler failures, including the SSRF rejection message.

---

## Development

```bash
corepack enable
pnpm install --no-frozen-lockfile --ignore-scripts
pnpm typecheck
pnpm build
pnpm test
```

The test suite uses `node:test` and Node's built-in `assert`. It is
split into:

- `tests/runtime.test.mjs` — SSRF, result helpers, Cloudflare error
  parsing.
- `tests/html.test.mjs` — page model and every findings generator,
  driven by HTML fixtures in `tests/fixtures/`.
- `tests/core.test.mjs` — TypeScript Core (compiled to `dist/`).
- `tests/mcp.test.mjs` — MCP protocol (initialize, server/discover,
  tools/list, tools/call, unknown tool, invalid JSON, notifications,
  SSRF defence).
- `tests/integration.test.mjs` — end-to-end runs of the portable
  runtime against a local HTTP fixture server.

The integration test sets `JEDAVID_TEST_ALLOW_LOOPBACK=1` so the
runtime can hit `127.0.0.1`. The dedicated SSRF tests in
`tests/mcp.test.mjs` explicitly disable that opt-in and verify that
localhost and private IPs are still blocked.

---

## CI

GitHub Actions runs on every push and pull request:

1. Manifest validation (`plugin.json`, `mcp.json`, `package.json`,
   `tsconfig.base.json`, `pnpm-workspace.yaml`).
2. Portable MCP smoke test (`tools/list`, `server/discover`,
   unknown-tool rejection, missing-method rejection).
3. `pnpm install` and `pnpm build` so the Core dist exists.
4. `pnpm typecheck`.
5. `pnpm test` (79 tests).
6. Skill sanity (every `SKILL.md` declares `name:` and
   `description:`).

CI does not require any secrets.

---

## License

MIT
