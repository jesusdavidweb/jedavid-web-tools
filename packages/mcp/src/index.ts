#!/usr/bin/env node
// Development MCP server. The portable runtime in `bin/` is the production
// distribution; this server uses the official MCP SDK and the typed Core
// to expose the same tool set over stdio for local debugging.
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod/v4';
import {
  auditSite, type FindingCategory, type Severity, summarizeFindings, sortFindings,
} from '@jedavid/web-tools-core';

const urlSchema = z.string().min(1).describe('Public HTTP(S) URL or hostname');
const categorySchema = z.array(z.enum(['performance', 'seo', 'security', 'accessibility'])).optional();

function resultContent(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

function createServer(): McpServer {
  const server = new McpServer(
    { name: 'jedavid-web-tools', version: '0.3.0' },
    {
      instructions: [
        'Read-only web engineering diagnostics.',
        'Use audit_site for a broad first pass; use the category-specific tools for narrow questions.',
        'Results are diagnostics, not authorization to modify a website.',
        'Prefer measurable root causes over score chasing.',
      ].join(' '),
    },
  );

  server.registerTool(
    'site_audit',
    {
      title: 'Audit website',
      description: 'Run a read-only website audit covering performance heuristics, technical SEO, security headers and static accessibility signals.',
      inputSchema: z.object({ url: urlSchema, categories: categorySchema }),
    },
    async ({ url, categories }) => {
      const result = await auditSite(url, { categories: categories as FindingCategory[] | undefined });
      const findings = sortFindings(result.findings);
      return resultContent({
        ok: true,
        tool: 'site_audit',
        target: url,
        summary: summarizeFindings(findings),
        findings,
        evidence: [{ type: 'http', summary: `HTTP ${result.status} in ${result.timing.responseMs} ms`, data: { headers: result.headers } }],
        metadata: { fetchedAt: result.fetchedAt, durationMs: result.timing.responseMs, version: '0.3.0' },
        data: {
          status: result.status,
          finalUrl: result.finalUrl,
          responseMs: result.timing.responseMs,
          htmlBytes: Buffer.byteLength(''),
          document: result.document,
          headers: result.headers,
        },
      });
    },
  );

  server.registerTool(
    'performance_audit',
    {
      title: 'Audit web performance',
      description: 'Inspect initial document latency, HTML weight, script/image heuristics and layout-risk signals.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => {
      const result = await auditSite(url, { categories: ['performance'] });
      const findings = sortFindings(result.findings);
      return resultContent({ ok: true, tool: 'performance_audit', target: url, summary: summarizeFindings(findings), findings, evidence: [], metadata: { version: '0.3.0' }, data: { responseMs: result.timing.responseMs, document: result.document } });
    },
  );

  server.registerTool(
    'seo_audit',
    {
      title: 'Audit technical SEO',
      description: 'Inspect title, description, canonical, language, headings, robots and JSON-LD presence.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => {
      const result = await auditSite(url, { categories: ['seo'] });
      const findings = sortFindings(result.findings);
      return resultContent({ ok: true, tool: 'seo_audit', target: url, summary: summarizeFindings(findings), findings, evidence: [], metadata: { version: '0.3.0' }, data: { document: result.document } });
    },
  );

  server.registerTool(
    'security_headers',
    {
      title: 'Audit security headers',
      description: 'Inspect common browser-facing security headers and obvious response metadata disclosure.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => {
      const result = await auditSite(url, { categories: ['security'] });
      const findings = sortFindings(result.findings);
      return resultContent({ ok: true, tool: 'security_headers', target: url, summary: summarizeFindings(findings), findings, evidence: [], metadata: { version: '0.3.0' }, data: { headers: result.headers, status: result.status } });
    },
  );

  server.registerTool(
    'accessibility_audit',
    {
      title: 'Audit accessibility',
      description: 'Run a static accessibility audit for language, alt text, labels, headings, landmarks and basic document signals.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => {
      const result = await auditSite(url, { categories: ['accessibility'] });
      const findings = sortFindings(result.findings);
      return resultContent({ ok: true, tool: 'accessibility_audit', target: url, summary: summarizeFindings(findings), findings, evidence: [], metadata: { version: '0.3.0' }, data: { document: result.document } });
    },
  );

  return server;
}

serveStdio(createServer);
