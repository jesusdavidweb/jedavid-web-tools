// bin/lib/write-tools.mjs
// Scaffolding for future write tools (destructive operations). NOT registered
// in the default tools list. Future versions of the toolkit may opt-in to
// specific write tools by:
//   1. Importing this module and registering the desired tools.
//   2. Setting MCP_ENABLE_WRITE_TOOLS=1 in the runtime environment.
//   3. Confirming that the runtime has been granted explicit permission
//      by the host (e.g. via an "Allow" prompt on the Agent Plugin).
//
// Any write tool registered through this module must:
//   - Set `annotations.destructiveHint: true`.
//   - Validate every argument against an allowlist.
//   - Require the host to pass `confirm: true` in arguments.
//   - Return a structured `ToolResult` with the operation id, the actor
//     (the runtime identity), the API request id when available, and
//     the diff against the previous state.
//
// This module intentionally does not implement any write handlers. It
// only documents the contract and provides the confirmation helper.

import { mkResult, mkFinding, SEVERITY } from './runtime.mjs';

export function confirmationRequired(operation) {
  return new Error(
    `Confirmation required: this is a destructive operation (${operation}). ` +
    'Pass `confirm: true` in the tool arguments to proceed. ' +
    'Read-only tools do not need confirmation.'
  );
}

export function assertConfirmed(args, operation) {
  if (!args || args.confirm !== true) throw confirmationRequired(operation);
}

export function writeToolEnvelope({ tool, target, operation, data, before, after, evidence, findings = [] }) {
  return mkResult(tool, target, data, {
    findings,
    evidence,
    summary: { operation, destructive: true },
    metadata: { operation, requiresConfirmation: true, destructive: true, before, after },
  });
}

// Example placeholder signatures for future write tools. These are
// intentionally NOT exported through the default TOOLS list. They show
// the shape a future implementation should follow.
export const reservedWriteTools = {
  // cloudflare_dns_create: requires CLOUDFLARE_API_TOKEN with zone:edit.
  // cloudflare_dns_update: requires CLOUDFLARE_API_TOKEN with zone:edit.
  // cloudflare_dns_delete: requires CLOUDFLARE_API_TOKEN with zone:edit.
  // cloudflare_cache_purge: requires CLOUDFLARE_API_TOKEN with zone:purge.
  // github_issue_create: requires GITHUB_TOKEN with repo:issues:write.
  // wordpress_plugin_update: requires WORDPRESS_APP_PASSWORD with update_plugins.
  // woocommerce_order_note_create: requires WOOCOMMERCE_KEY/SECRET with write.
  // docker_container_restart: requires local Docker CLI + explicit allowlist.
  // deployment_rollback: requires deployment platform credentials.
};

// The contract every future write tool must satisfy:
//
//   1. The tool is registered with:
//        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: <per tool> }
//
//   2. The inputSchema requires `confirm: { type: 'boolean', const: true }`.
//
//   3. The handler calls `assertConfirmed(args, '<operation name>')` first.
//
//   4. The handler validates every user-supplied identifier against a
//      strict allowlist (e.g. `^[A-Za-z0-9_.-]+$`) and rejects anything
//      that does not match — without round-tripping to the API.
//
//   5. The handler never accepts credentials as arguments. It reads them
//      from the MCP runtime environment.
//
//   6. The handler returns a `writeToolEnvelope({...})` that includes:
//        - `before`: the prior state (when applicable, e.g. DNS record).
//        - `after`: the new state.
//        - `evidence`: the upstream API request/response (with secrets
//          redacted).
//
//   7. The handler never prints the credential, the secret or any token
//      in any field of the response.

export const writeToolContract = Object.freeze({
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  requiredArgKeys: ['confirm'],
  allowlists: { name: /^[A-Za-z0-9_.-]+$/, repo: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/ },
  example: {
    cloudflare_dns_create: {
      name: 'cloudflare_dns_create',
      title: 'Create a Cloudflare DNS record',
      description: 'Create a DNS record in a Cloudflare zone. Requires CLOUDFLARE_API_TOKEN with zone:edit and `confirm: true`.',
      inputSchema: {
        type: 'object',
        properties: {
          zone: { type: 'string', minLength: 1, description: 'Zone domain (e.g. example.com).' },
          type: { type: 'string', enum: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS'] },
          name: { type: 'string', description: 'Record name (relative to the zone).' },
          content: { type: 'string', description: 'Record value.' },
          ttl: { type: 'integer', minimum: 60, maximum: 86400, default: 1, description: 'TTL in seconds (1 = automatic).' },
          proxied: { type: 'boolean', default: false },
          confirm: { type: 'boolean', const: true, description: 'Must be true. Confirms the destructive operation.' },
        },
        required: ['zone', 'type', 'name', 'content', 'confirm'],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
  },
});
