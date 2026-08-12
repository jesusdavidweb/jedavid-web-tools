# jedavid-web-tools

Portable, read-only web engineering tools for AI coding agents. The same repository can be imported as an **Agent Plugins 1.0** plugin and used by MCP-capable clients such as MiniMax, Claude and Codex-compatible runtimes.

## Portable plugin layout

```text
plugin.json
mcp.json
bin/jedavid-web-tools-mcp.mjs
skills/
  web-audit/
  platform-ops/
  wordpress-commerce/
packages/
  core/
  cli/
  mcp/
```

The portable MCP runtime in `bin/` has **zero npm runtime dependencies**. This is intentional: a client importing the GitHub repository does not need to run `pnpm install` before starting the MCP server. The TypeScript packages remain the development/library surface.

## MCP tools

### Web engineering

- `site_audit`
- `http_inspect`
- `performance_audit`
- `performance_assets`
- `seo_audit`
- `seo_schema`
- `seo_indexability`
- `seo_links`
- `seo_llm`
- `accessibility_audit`
- `security_headers`
- `security_cookies`
- `stack_detect`
- `robots_inspect`
- `sitemap_inspect`
- `page_compare`

### Cloudflare

- `cloudflare_zone`
- `cloudflare_dns`
- `cloudflare_workers`

Environment: `CLOUDFLARE_API_TOKEN`, and `CLOUDFLARE_ACCOUNT_ID` for Workers.

### GitHub

- `github_repo`
- `github_actions`

Optional environment: `GITHUB_TOKEN`.

### WordPress / WooCommerce

- `wordpress_rest_index`
- `wordpress_plugins`
- `woocommerce_system_status`
- `woocommerce_webhooks`

Environment:

```text
WORDPRESS_BASE_URL
WORDPRESS_USERNAME
WORDPRESS_APP_PASSWORD
WOOCOMMERCE_BASE_URL
WOOCOMMERCE_KEY
WOOCOMMERCE_SECRET
```

Use read-only credentials wherever possible.

### Docker

- `docker_ps`
- `docker_inspect`
- `docker_logs`

These tools require the Docker CLI and access to the local Docker daemon. They never restart, stop, delete or mutate containers.

## Security model

The portable plugin is intentionally **read-only**. Public URL fetchers reject localhost/private network destinations and validate every redirect target to reduce SSRF exposure. Credentials are never accepted as MCP tool arguments; integrations read credentials from the MCP runtime environment.

## MCP compatibility

The standalone server supports the modern MCP `server/discover` flow for protocol `2026-07-28` and legacy `initialize` negotiation for older clients. Stdio messages are newline-delimited JSON-RPC.

## Local development

```bash
corepack enable
pnpm install
pnpm typecheck
pnpm build
```

Run the portable MCP server directly:

```bash
node bin/jedavid-web-tools-mcp.mjs
```

Or run the TypeScript development server:

```bash
pnpm mcp
```

## Agent Plugins import

Import the public repository URL in an Agent Plugins 1.0 client:

```text
https://github.com/jesusdavidweb/jedavid-web-tools
```

A conforming client should discover **3 skills** and **1 MCP server**.

## Roadmap

The next layer is browser-backed lab measurement (Chromium/CDP/Lighthouse/CrUX) as an optional adapter. It is intentionally not required by the portable runtime because bundling a browser would make GitHub plugin import heavy and platform-specific.

## License

MIT
