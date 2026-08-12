#!/usr/bin/env node
import { auditSite, type AuditCategory, type AuditFinding } from '@jedavid/web-tools-core';

function usage(): never {
  console.error(`Usage:
  jedavid-web-tools audit <url> [--category=performance,seo,security] [--json]

Examples:
  jedavid-web-tools audit https://example.com
  jedavid-web-tools audit example.com --category=performance,seo
  jedavid-web-tools audit example.com --json`);
  process.exit(1);
}

function parseCategories(value?: string): AuditCategory[] | undefined {
  if (!value) return undefined;
  const allowed = new Set<AuditCategory>(['performance', 'seo', 'security']);
  const parsed = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (parsed.some((item) => !allowed.has(item as AuditCategory))) {
    throw new Error(`Invalid category. Allowed values: ${[...allowed].join(', ')}`);
  }
  return parsed as AuditCategory[];
}

function icon(finding: AuditFinding): string {
  if (finding.severity === 'error') return 'ERROR';
  if (finding.severity === 'warning') return 'WARN ';
  return 'INFO ';
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const url = args[1];
  if (command !== 'audit' || !url) usage();

  const json = args.includes('--json');
  const categoryArg = args.find((arg) => arg.startsWith('--category='));
  const categories = parseCategories(categoryArg?.slice('--category='.length));
  const result = await auditSite(url, { categories });

  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  console.log(`${result.finalUrl} — HTTP ${result.status}`);
  console.log(`Document response: ${result.timing.responseMs} ms | HTML: ${(result.document.htmlBytes / 1024).toFixed(1)} KiB`);
  console.log(`Findings: ${result.summary.errors} errors, ${result.summary.warnings} warnings, ${result.summary.info} info\n`);

  if (result.findings.length === 0) {
    console.log('No findings for the selected categories.');
    return;
  }

  for (const finding of result.findings) {
    console.log(`[${icon(finding)}] ${finding.category}/${finding.id}: ${finding.title}`);
    console.log(`  ${finding.detail}`);
    if (finding.recommendation) console.log(`  → ${finding.recommendation}`);
  }

  if (result.summary.errors > 0) process.exitCode = 2;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`jedavid-web-tools: ${message}`);
  process.exit(1);
});
