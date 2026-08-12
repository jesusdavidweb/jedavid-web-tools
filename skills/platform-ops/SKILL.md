---
name: platform-ops
description: Diagnose Cloudflare, GitHub and local Docker state using read-only jedavid-web-tools MCP tools.
---

# Platform Operations Diagnostics

Use these tools only for inspection and diagnosis. Never claim a mutation occurred.

## Cloudflare

Configure `CLOUDFLARE_API_TOKEN` in the MCP runtime environment. For
account-scoped tools also configure `CLOUDFLARE_ACCOUNT_ID`. Use a
least-privilege read token.

Workflow:
1. `cloudflare_account` to confirm the account metadata.
2. `cloudflare_zones` to list the zones visible to the token.
3. `cloudflare_zone` to inspect a specific zone (status, plan, name servers).
4. `cloudflare_dns` to enumerate records (optionally filtered by type).
5. `cloudflare_workers`, `cloudflare_pages`, `cloudflare_d1`, `cloudflare_r2`,
   `cloudflare_kv`, `cloudflare_queues` to inventory account-scoped products.
6. `cloudflare_access` to list Access applications.

Permission errors are returned as `Cloudflare API: <message>` and, when
detectable, include a hint about the required scope. Never paste a token
into a tool argument — credentials belong in the MCP runtime environment.

## GitHub

Public repositories work without a token. Private repos and rate-limited
access use `GITHUB_TOKEN`.

Workflow:
1. `github_repo` for metadata (default branch, visibility, license, topics).
2. `github_branches` for the active branch list and protection flags.
3. `github_pull_requests` (state = open/closed/all) and `github_issues` for
   the work in flight.
4. `github_actions` for recent runs; `github_workflow_runs` to drill into a
   specific workflow file.
5. `github_releases` to inspect published versions.
6. `github_deployments` to confirm deployment activity.

## Docker

Requires the Docker CLI and permission to access the local daemon. All
Docker tools are read-only and never restart, stop, delete or mutate
containers.

Workflow:
1. `docker_ps` to enumerate local containers.
2. `docker_inspect` for one container's metadata. Secret-looking env vars
   are redacted automatically.
3. `docker_logs` for a bounded tail (max 500 lines).
4. `docker_stats` for a one-shot CPU/memory/IO snapshot.
5. `docker_images`, `docker_networks`, `docker_volumes` for inventory.
6. `docker_compose_status` to read the current compose project's service
   state.

Treat logs as potentially sensitive and summarize only what is needed.

## General workflow

Inspect → identify evidence → explain likely cause → recommend the smallest
next action. Do not perform writes, restarts or deletes.
