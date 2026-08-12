#!/usr/bin/env node
import { auditSite, type AuditCategory } from '@jedavid/web-tools-core';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';

const urlSchema = z.string().min(1).describe('HTTP(S) URL or hostname to audit');

function resultContent(value: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }],
  };
}

function createServer(): McpServer {
  const server = new McpServer(
    { name: 'jedavid-web-tools', version: '0.1.0' },
    {
      instructions: [
        'Use audit_site for a broad first pass.',
        'Use category-specific tools when only one domain is relevant.',
        'Treat results as diagnostics, not permission to modify a website or repository.',
        'Prefer measurable root causes over score chasing.',
      ].join(' '),
    },
  );

  server.registerTool(
    'audit_site',
    {
      title: 'Audit website',
      description: 'Run a read-only website audit covering performance heuristics, technical SEO and security headers.',
      inputSchema: z.object({
        url: urlSchema,
        categories: z.array(z.enum(['performance', 'seo', 'security'])).optional(),
      }),
    },
    async ({ url, categories }) => resultContent(await auditSite(url, { categories: categories as AuditCategory[] | undefined })),
  );

  server.registerTool(
    'performance_audit',
    {
      title: 'Audit web performance',
      description: 'Inspect initial document latency, HTML weight, script/image heuristics and layout-risk signals.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => resultContent(await auditSite(url, { categories: ['performance'] })),
  );

  server.registerTool(
    'seo_audit',
    {
      title: 'Audit technical SEO',
      description: 'Inspect title, description, canonical, language, headings, robots and JSON-LD presence.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => resultContent(await auditSite(url, { categories: ['seo'] })),
  );

  server.registerTool(
    'security_headers',
    {
      title: 'Audit security headers',
      description: 'Inspect common browser-facing security headers and obvious response metadata disclosure.',
      inputSchema: z.object({ url: urlSchema }),
    },
    async ({ url }) => resultContent(await auditSite(url, { categories: ['security'] })),
  );

  return server;
}

serveStdio(createServer);
