#!/usr/bin/env node
import { auditSite, type Finding, type FindingCategory, type Severity, sortFindings, summarizeFindings } from '@jedavid/web-tools-core';

function usage(): never {
  console.error(`Usage:
  jedavid-web-tools audit <url> [--category=performance,seo,security,accessibility] [--json] [--no-truncate]

Categories:
  performance seo security accessibility

Examples:
  jedavid-web-tools audit https://example.com
  jedavid-web-tools audit example.com --category=performance,seo
  jedavid-web-tools audit example.com --json`);
  process.exit(1);
}

function parseCategories(value?: string): FindingCategory[] | undefined {
  if (!value) return undefined;
  const allowed: FindingCategory[] = ['performance', 'seo', 'security', 'accessibility'];
  const parsed = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const p of parsed) {
    if (!allowed.includes(p as FindingCategory)) {
      throw new Error(`Invalid category. Allowed values: ${allowed.join(', ')}`);
    }
  }
  return parsed as FindingCategory[];
}

const SEVERITY_ICON: Record<Severity, string> = {
  info: 'INFO ',
  low: 'LOW  ',
  medium: 'MED  ',
  high: 'HIGH ',
  critical: 'CRIT ',
};

function icon(s: Severity): string { return SEVERITY_ICON[s] || s.toUpperCase(); }

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const url = args[1];
  if (command !== 'audit' || !url) usage();
  const json = args.includes('--json');
  const categoryArg = args.find((a) => a.startsWith('--category='));
  const categories = parseCategories(categoryArg?.slice('--category='.length));
  const result = await auditSite(url, { categories });

  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  console.log(`${result.finalUrl} — HTTP ${result.status}`);
  console.log(`Response: ${result.timing.responseMs} ms | HTML: ${(result.document.title || '(no title)').slice(0, 60)}`);
  const findings = sortFindings(result.findings);
  const summary = summarizeFindings(findings);
  console.log(`Findings: ${summary.total} total — ${Object.entries(summary.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ')}\n`);

  if (findings.length === 0) {
    console.log('No findings for the selected categories.');
    return;
  }
  for (const finding of findings) {
    console.log(`[${icon(finding.severity)}] ${finding.category}/${finding.id}: ${finding.title}`);
    console.log(`  ${finding.description}`);
    if (finding.recommendation) console.log(`  → ${finding.recommendation}`);
  }
  if ((summary.bySeverity.critical || 0) > 0 || (summary.bySeverity.high || 0) > 0) process.exitCode = 2;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`jedavid-web-tools: ${message}`);
  process.exit(1);
});
