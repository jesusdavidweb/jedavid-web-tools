---
name: platform-ops
description: Diagnose Cloudflare, GitHub and local Docker state using read-only jedavid-web-tools MCP tools.
---

# Platform Operations Diagnostics

Use these tools only for inspection and diagnosis. Never claim a mutation occurred.

## Cloudflare

Use `cloudflare_zone`, `cloudflare_dns`, and `cloudflare_workers`. They require `CLOUDFLARE_API_TOKEN`; Workers also requires `CLOUDFLARE_ACCOUNT_ID`. Prefer least-privilege read tokens.

## GitHub

Use `github_repo` and `github_actions`. Public repositories work without a token; private/rate-limited access can use `GITHUB_TOKEN`.

## Docker

Use `docker_ps`, `docker_inspect`, and `docker_logs` only when the runtime has the Docker CLI and permission to access the daemon. Treat logs as potentially sensitive and summarize only what is needed.

## Workflow

Inspect -> identify evidence -> explain likely cause -> recommend the smallest next action. Do not perform writes or restarts.
