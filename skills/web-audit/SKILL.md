---
name: web-audit
description: Audit a website for web performance, technical SEO, and HTTP security issues using jedavid-web-tools. Use when the user asks to analyze, audit, diagnose, optimize, compare, or improve a production website or web project.
license: MIT
compatibility: Requires Node.js 22+ and network access. For local execution, install repository dependencies with pnpm before invoking the CLI or MCP server.
metadata:
  author: jesusdavidweb
  version: "0.1.0"
---

# Web Audit

Use `jedavid-web-tools` as the measurement layer. Do not infer performance or SEO problems from source code alone when the production URL can be measured.

## Workflow

1. Establish the target production URL and scope.
2. Run a baseline audit before changing code.
3. Prioritize findings by severity and measurable user impact.
4. If a repository is available, locate the source responsible for each important finding.
5. Prefer minimal fixes that preserve functionality, analytics, SEO content, and UX.
6. Build and test the project after changes.
7. Re-run the same audit and compare before/after results.
8. Report remaining limitations separately from verified improvements.

## Local CLI

From the plugin/repository root, ensure dependencies are installed once:

```bash
pnpm install
```

Run a complete audit:

```bash
pnpm audit -- https://example.com
```

Use JSON output when another agent or script will consume the result:

```bash
pnpm audit -- https://example.com --json
```

## Priorities

For performance work, prioritize real bottlenecks over cosmetic score chasing. For SEO, protect indexability, canonicalization, metadata, structured data, and crawlability. For security, distinguish missing hardening headers from actual exploitable vulnerabilities.

## Guardrails

Do not remove required features, analytics, consent systems, structured data, or customer-facing functionality merely to improve an audit score. Do not make destructive infrastructure changes without explicit approval.
