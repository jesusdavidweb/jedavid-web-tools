# jedavid-web-tools

Reusable web engineering tools for AI coding agents, CLI workflows and CI.

The project exposes one shared TypeScript core through two interfaces:

- **CLI** for local scripts and CI.
- **MCP** for Codex, Claude, MiniMax and other MCP-compatible agents.

## V1 capabilities

### Performance
- Initial HTML response timing.
- HTML transfer size.
- Script, stylesheet and image counts.
- Lazy-loading heuristics.
- Missing image dimensions / layout-shift risk.
- Mobile viewport detection.

### Technical SEO
- Title and meta description.
- Canonical URL.
- Document language.
- H1 structure.
- robots/noindex detection.
- JSON-LD presence.

### Security
- HSTS.
- Content-Security-Policy.
- X-Content-Type-Options.
- Referrer-Policy.
- Permissions-Policy.
- Basic server version disclosure detection.

All current tools are **read-only**.

## Architecture

```text
packages/core  -> shared audit engine
packages/cli   -> command-line interface
packages/mcp   -> stdio MCP server
```

Future modules can extend the same core with browser/CDP metrics, Lighthouse, CrUX, Cloudflare, WordPress/WooCommerce, Docker/Dokploy and GitHub adapters.

## Requirements

- Node.js 22+
- pnpm 11+

## Install

```bash
corepack enable
pnpm install
pnpm build
```

## CLI

```bash
pnpm audit -- audit https://example.com
pnpm audit -- audit https://example.com --category=performance,seo
pnpm audit -- audit https://example.com --json
```

After building the CLI package directly:

```bash
node packages/cli/dist/index.js audit https://example.com
```

Exit codes:

- `0`: completed without error-severity findings.
- `1`: command/runtime error.
- `2`: audit completed with one or more error-severity findings.

## MCP

Development:

```bash
pnpm mcp
```

Built server:

```bash
node /absolute/path/to/jedavid-web-tools/packages/mcp/dist/index.js
```

Exposed tools:

- `audit_site`
- `performance_audit`
- `seo_audit`
- `security_headers`

### Generic stdio MCP configuration

Use the equivalent MCP configuration format supported by your client:

```json
{
  "mcpServers": {
    "jedavid-web-tools": {
      "command": "node",
      "args": [
        "/absolute/path/to/jedavid-web-tools/packages/mcp/dist/index.js"
      ]
    }
  }
}
```

The server is intentionally agent-agnostic. Codex, Claude and MiniMax should consume the same MCP backend; provider-specific instructions/skills belong outside the core.

## Recommended agent workflow

```text
1. audit_site
2. inspect the highest-severity findings
3. inspect the source repository
4. identify the root cause
5. make the smallest safe change
6. build/test
7. audit again
8. compare measurable results
```

Do not optimize solely for a Lighthouse score and do not remove analytics, functionality, accessibility or SEO content just to improve synthetic performance metrics.

## Development

```bash
pnpm typecheck
pnpm build
```

## Roadmap

- Browser/CDP network waterfall and real resource timing.
- Lighthouse lab metrics and before/after comparison.
- CrUX field data integration.
- Asset/image/font analysis.
- JavaScript execution and hydration diagnostics.
- Accessibility auditing.
- Cloudflare read/write tools with explicit mutation permissions.
- WordPress/WooCommerce diagnostics.
- Docker/Dokploy diagnostics.
- GitHub/CI performance budgets.

## License

MIT
