// tests/runtime.test.mjs
// Unit tests for the low-level runtime helpers.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  isPrivateIpv4, isPrivateIpv6, isPrivateIp,
  normalizeHostname,
  mkResult, mkFinding, mkEvidence, summarizeFindings, sortFindings,
  describeCloudflareError,
  SEVERITY, VERSION,
} from '../bin/lib/runtime.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const skillsDir = path.resolve(__dirname, '..', 'skills');

// Regression guard: the Agent Skills spec requires that the YAML frontmatter
// of every SKILL.md parse as plain scalars. The character sequences ": "
// (colon + space) and " #" (space + hash) are explicitly forbidden because
// they are ambiguous with key/value separators and comments in plain style.
// We previously shipped a skill whose description contained "tools: TTFB"
// and MiniMax silently skipped it on import.
test('all skills declare valid Agent Skills frontmatter', () => {
  const dirs = fs.readdirSync(skillsDir);
  const errors = [];
  for (const d of dirs) {
    const file = path.join(skillsDir, d, 'SKILL.md');
    if (!fs.existsSync(file)) { errors.push(`${file}: missing`); continue; }
    const content = fs.readFileSync(file, 'utf8');
    const m = content.match(/^---\n([\s\S]*?)\n---\n/);
    if (!m) { errors.push(`${file}: no frontmatter`); continue; }
    const fm = {};
    for (const line of m[1].split('\n')) {
      const i = line.indexOf(':');
      if (i < 0) continue;
      fm[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    if (!fm.name) errors.push(`${file}: missing name`);
    if (!fm.description) errors.push(`${file}: missing description`);
    if (fm.name !== d) errors.push(`${file}: name "${fm.name}" != dir "${d}"`);
    if (fm.name) {
      if (!/^[a-z0-9-]+$/.test(fm.name)) errors.push(`${file}: name has invalid chars`);
      if (fm.name.startsWith('-') || fm.name.endsWith('-')) errors.push(`${file}: name starts/ends with hyphen`);
      if (fm.name.includes('--')) errors.push(`${file}: name has consecutive hyphens`);
      if (fm.name.length > 64) errors.push(`${file}: name too long`);
    }
    if (fm.description && fm.description.length > 1024) errors.push(`${file}: description too long`);
    for (const k of ['name', 'description']) {
      if (fm[k] && /: /.test(fm[k])) errors.push(`${file}: ${k} contains ": " (breaks plain-scalar YAML)`);
      if (fm[k] && / #/.test(fm[k])) errors.push(`${file}: ${k} contains " #" (breaks plain-scalar YAML)`);
    }
  }
  assert.deepEqual(errors, [], `Skill validation errors:\n${errors.join('\n')}`);
});

test('isPrivateIpv4: known private ranges', () => {
  assert.equal(isPrivateIpv4('10.0.0.1'), true);
  assert.equal(isPrivateIpv4('172.16.0.1'), true);
  assert.equal(isPrivateIpv4('172.31.255.254'), true);
  assert.equal(isPrivateIpv4('192.168.1.1'), true);
  assert.equal(isPrivateIpv4('127.0.0.1'), true);
  assert.equal(isPrivateIpv4('169.254.169.254'), true); // AWS metadata
  assert.equal(isPrivateIpv4('100.64.0.1'), true); // CGNAT
  assert.equal(isPrivateIpv4('0.0.0.0'), true);
  assert.equal(isPrivateIpv4('192.0.2.1'), true); // TEST-NET-1
  assert.equal(isPrivateIpv4('198.51.100.1'), true); // TEST-NET-2
  assert.equal(isPrivateIpv4('203.0.113.1'), true); // TEST-NET-3
  assert.equal(isPrivateIpv4('224.0.0.1'), true); // multicast
  assert.equal(isPrivateIpv4('255.255.255.255'), true); // broadcast
  assert.equal(isPrivateIpv4('198.18.0.0'), true); // benchmark
});

test('isPrivateIpv4: public IPs', () => {
  assert.equal(isPrivateIpv4('8.8.8.8'), false);
  assert.equal(isPrivateIpv4('1.1.1.1'), false);
  assert.equal(isPrivateIpv4('93.184.216.34'), false);
  assert.equal(isPrivateIpv4('172.32.0.1'), false);
  assert.equal(isPrivateIpv4('172.15.0.1'), false);
  assert.equal(isPrivateIpv4('11.0.0.1'), false);
});

test('isPrivateIpv4: malformed input', () => {
  assert.equal(isPrivateIpv4('not.an.ip'), true);
  assert.equal(isPrivateIpv4('1.2.3'), true);
  assert.equal(isPrivateIpv4('1.2.3.4.5'), true);
  assert.equal(isPrivateIpv4('256.0.0.0'), true);
  assert.equal(isPrivateIpv4(''), true);
  assert.equal(isPrivateIpv4(null), true);
});

test('isPrivateIpv6: known special ranges', () => {
  assert.equal(isPrivateIpv6('::1'), true);
  assert.equal(isPrivateIpv6('::'), true);
  assert.equal(isPrivateIpv6('fc00::1'), true);
  assert.equal(isPrivateIpv6('fd00::1'), true);
  assert.equal(isPrivateIpv6('fe80::1'), true);
  assert.equal(isPrivateIpv6('ff02::1'), true);
  assert.equal(isPrivateIpv6('2001:db8::1'), true);
  assert.equal(isPrivateIpv6('::ffff:127.0.0.1'), true); // IPv4-mapped loopback
  assert.equal(isPrivateIpv6('::ffff:10.0.0.1'), true); // IPv4-mapped private
  assert.equal(isPrivateIpv6('2002:0a00:0001::'), true); // 6to4 10.0.0.1
  assert.equal(isPrivateIpv6('2002:7f00:0001::'), true); // 6to4 127.0.0.1
  assert.equal(isPrivateIpv6('2002:0a00:0001::'), true); // 6to4 10.0.0.1
  assert.equal(isPrivateIpv6('::ffff:8.8.8.8'), false); // IPv4-mapped public
});

test('isPrivateIpv6: public IPs', () => {
  assert.equal(isPrivateIpv6('2606:4700:4700::1111'), false); // Cloudflare DNS
  assert.equal(isPrivateIpv6('2001:4860:4860::8888'), false); // Google
});

test('isPrivateIp dispatches by family', () => {
  assert.equal(isPrivateIp('10.0.0.1'), true);
  assert.equal(isPrivateIp('::1'), true);
  assert.equal(isPrivateIp('1.1.1.1'), false);
});

test('normalizeHostname handles common cases', () => {
  assert.equal(normalizeHostname('  Example.com.  '), 'example.com');
  assert.equal(normalizeHostname('localhost'), 'localhost');
  assert.equal(normalizeHostname('0.0.0.0'), null);
  assert.equal(normalizeHostname('0'), null);
  assert.equal(normalizeHostname('host with space'), null);
  assert.equal(normalizeHostname('host?with#query'), null);
  assert.equal(normalizeHostname(''), null);
  assert.equal(normalizeHostname(null), null);
});

test('mkResult builds the standard envelope', () => {
  const r = mkResult('tool', 'target', { foo: 1 }, { findings: [], summary: { total: 0 } });
  assert.equal(r.ok, true);
  assert.equal(r.tool, 'tool');
  assert.equal(r.target, 'target');
  assert.deepEqual(r.data, { foo: 1 });
  assert.equal(r.metadata.version, VERSION);
  assert.ok(r.metadata.fetchedAt);
});

test('mkFinding produces a complete finding', () => {
  const f = mkFinding({ id: 'a.b', severity: SEVERITY.HIGH, category: 'test', title: 'T', description: 'D', recommendation: 'R', evidence: { x: 1 } });
  assert.equal(f.id, 'a.b');
  assert.equal(f.severity, 'high');
  assert.equal(f.category, 'test');
  assert.deepEqual(f.evidence, { x: 1 });
});

test('summarizeFindings aggregates counts', () => {
  const f = [
    mkFinding({ id: 'a', severity: SEVERITY.HIGH, category: 'seo', title: 'a', description: 'a' }),
    mkFinding({ id: 'b', severity: SEVERITY.MEDIUM, category: 'seo', title: 'b', description: 'b' }),
    mkFinding({ id: 'c', severity: SEVERITY.MEDIUM, category: 'security', title: 'c', description: 'c' }),
  ];
  const s = summarizeFindings(f);
  assert.equal(s.total, 3);
  assert.equal(s.bySeverity.high, 1);
  assert.equal(s.bySeverity.medium, 2);
  assert.equal(s.byCategory.seo, 2);
  assert.equal(s.byCategory.security, 1);
});

test('sortFindings orders by severity desc', () => {
  const f = [
    mkFinding({ id: 'a', severity: SEVERITY.INFO, category: 'x', title: 'a', description: 'a' }),
    mkFinding({ id: 'b', severity: SEVERITY.CRITICAL, category: 'x', title: 'b', description: 'b' }),
    mkFinding({ id: 'c', severity: SEVERITY.MEDIUM, category: 'x', title: 'c', description: 'c' }),
  ];
  const sorted = sortFindings(f);
  assert.equal(sorted[0].id, 'b');
  assert.equal(sorted[1].id, 'c');
  assert.equal(sorted[2].id, 'a');
});

test('describeCloudflareError extracts the scope hint', () => {
  const a = describeCloudflareError(new Error('Cloudflare API: Missing required permission zone:read'));
  assert.match(a, /Missing required permission/);
  assert.match(a, /likely required scope/);
  assert.match(a, /zone:read/);

  const b = describeCloudflareError(new Error('Cloudflare API: Missing permissions for account. Need permission dns_records:read.'));
  assert.match(b, /likely required scope/);

  const c = describeCloudflareError(new Error('Cloudflare API: Authentication error.'));
  assert.equal(c, 'Cloudflare API: Authentication error.');
});

test('SEVERITY exposes the canonical strings', () => {
  assert.equal(SEVERITY.CRITICAL, 'critical');
  assert.equal(SEVERITY.HIGH, 'high');
  assert.equal(SEVERITY.MEDIUM, 'medium');
  assert.equal(SEVERITY.LOW, 'low');
  assert.equal(SEVERITY.INFO, 'info');
});
