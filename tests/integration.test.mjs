// tests/integration.test.mjs
// End-to-end tests that drive the portable MCP runtime against a local
// fixture HTTP server. These verify that the tool handlers correctly produce
// the standardized result envelope for a real page response.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startFixtureServer, stopFixtureServer } from './helpers/fixture-server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const bin = path.join(root, 'bin', 'jedavid-web-tools-mcp.mjs');

async function withServer(fn) {
  const srv = await startFixtureServer();
  try { return await fn(srv); } finally { await stopFixtureServer(srv.server); }
}

function call(lines, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin], { cwd: root, env: { ...process.env, JEDAVID_TEST_ALLOW_LOOPBACK: '1', ...env } });
    let buffer = '';
    const messages = [];
    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try { messages.push(JSON.parse(line)); } catch { /* ignore */ }
      }
    });
    child.on('error', reject);
    child.on('close', () => resolve(messages));
    for (const l of lines) child.stdin.write(l + '\n');
    child.stdin.end();
  });
}

function callTool(name, args, env) {
  return call([JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })], env).then((m) => {
    const resp = m[0];
    if (!resp) throw new Error('no response');
    if (resp.error) {
      const e = new Error(resp.error.message);
      e.code = resp.error.code;
      throw e;
    }
    // tools/call wraps the handler result in an MCP envelope with
    // `content` (text) and `structuredContent` (object). Prefer the
    // structured form so tests can read fields directly.
    if (resp.result && resp.result.structuredContent) return resp.result.structuredContent;
    if (resp.result && resp.result.content && resp.result.content[0] && resp.result.content[0].text) {
      try { return JSON.parse(resp.result.content[0].text); } catch { return resp.result; }
    }
    return resp.result;
  });
}

test('site_audit returns the standardized envelope with findings', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('site_audit', { url: `${baseUrl}/basic` });
    assert.equal(r.ok, true);
    assert.equal(r.tool, 'site_audit');
    assert.equal(r.target, `${baseUrl}/basic`);
    assert.ok(r.summary);
    assert.ok(Array.isArray(r.findings));
    assert.ok(Array.isArray(r.evidence));
    assert.ok(r.metadata);
    assert.equal(r.metadata.version.length > 0, true);
    // data envelope
    assert.equal(r.data.response.status, 200);
    assert.equal(r.data.document.title.length > 0, true);
    assert.equal(r.data.document.lang, 'en');
    assert.ok(Array.isArray(r.data.stack));
  });
});

test('http_inspect reports status, headers and content-type', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('http_inspect', { url: `${baseUrl}/basic` });
    assert.equal(r.ok, true);
    assert.equal(r.data.status, 200);
    assert.equal(r.data.contentType.startsWith('text/html'), true);
    assert.ok(r.data.headers);
    assert.ok(typeof r.data.responseMs === 'number');
  });
});

test('http_inspect follows redirects and reports the final URL', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('http_inspect', { url: `${baseUrl}/redirect/a` });
    assert.equal(r.data.status, 200);
    assert.equal(r.data.finalUrl, `${baseUrl}/basic`);
    assert.ok(r.data.redirected >= 1);
  });
});

test('security_headers flags missing headers on the basic page', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('security_headers', { url: `${baseUrl}/basic` });
    assert.equal(r.ok, true);
    assert.ok(r.findings.length > 0);
    for (const f of r.findings) {
      assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(f.severity));
    }
  });
});

test('security_headers on the secure page surfaces no critical findings', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('security_headers', { url: `${baseUrl}/secure` });
    assert.equal(r.ok, true);
    const blocking = r.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
    assert.equal(blocking.length, 0);
  });
});

test('security_cookies inspects Set-Cookie attributes', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('security_cookies', { url: `${baseUrl}/cookies` });
    assert.equal(r.ok, true);
    assert.ok(r.data.count >= 1);
    const sid = r.findings.filter((x) => x.title.includes('sid'));
    assert.ok(sid.length > 0);
  });
});

test('seo_audit returns a subset of site_audit findings', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('seo_audit', { url: `${baseUrl}/basic` });
    assert.equal(r.ok, true);
    for (const f of r.findings) {
      assert.ok(['seo', 'llm', 'accessibility'].includes(f.category) || f.id.startsWith('schema.') || f.id.startsWith('links.'));
    }
  });
});

test('seo_schema extracts two valid JSON-LD blocks with multiple types', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('seo_schema', { url: `${baseUrl}/basic` });
    assert.equal(r.data.blocksTotal, 2);
    assert.equal(r.data.blocksValid, 2);
    assert.equal(r.data.blocksInvalid, 0);
    assert.ok(r.data.types.includes('WebSite'));
    assert.ok(r.data.types.includes('Organization'));
  });
});

test('seo_schema reports invalid JSON-LD', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('seo_schema', { url: `${baseUrl}/broken-schema` });
    assert.equal(r.data.blocksInvalid, 1);
    assert.equal(r.data.blocksValid, 0);
  });
});

test('seo_links classifies internal vs external and detects nofollow', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('seo_links', { url: `${baseUrl}/basic` });
    assert.ok(r.data.total > 0);
    assert.ok(r.data.internal > 0);
    assert.ok(r.data.external > 0);
    assert.ok(r.data.nofollow > 0);
  });
});

test('stack_detect identifies WordPress and Next.js from fixtures', async () => {
  await withServer(async ({ baseUrl }) => {
    const wp = await callTool('stack_detect', { url: `${baseUrl}/wordpress` });
    assert.ok(wp.data.technologies.some((t) => t.name === 'WordPress'));
    const nx = await callTool('stack_detect', { url: `${baseUrl}/nextjs` });
    assert.ok(nx.data.technologies.some((t) => t.name === 'Next.js'));
  });
});

test('robots_inspect parses user-agents, disallow and sitemaps', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('robots_inspect', { url: baseUrl });
    assert.equal(r.data.present, true);
    assert.ok(r.data.userAgents.includes('*'));
    assert.ok(r.data.disallow.includes('/private/'));
    assert.ok(r.data.sitemaps.some((s) => s.includes('sitemap.xml')));
  });
});

test('sitemap_inspect identifies a urlset with entries', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('sitemap_inspect', { url: baseUrl });
    assert.equal(r.data.type, 'urlset');
    assert.equal(r.data.total, 2);
  });
});

test('seo_llm reports llms.txt presence and AI crawler coverage', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('seo_llm', { url: `${baseUrl}/basic` });
    assert.equal(r.data.llmsTxt.present, true);
    assert.ok(r.data.aiCrawlerMentions.GPTBot === false);
    assert.ok(r.data.semantic.title.length > 0);
  });
});

test('page_compare reports deltas between two pages', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('page_compare', { before: `${baseUrl}/basic`, after: `${baseUrl}/empty` });
    assert.equal(r.data.before, `${baseUrl}/basic`);
    assert.equal(r.data.after, `${baseUrl}/empty`);
    assert.equal(typeof r.data.findings.delta, 'number');
  });
});

test('redirect_trace returns the hop list', async () => {
  await withServer(async ({ baseUrl }) => {
    const r = await callTool('redirect_trace', { url: `${baseUrl}/redirect/a` });
    assert.ok(r.data.hops.length >= 3);
    assert.equal(r.data.final.url, `${baseUrl}/basic`);
  });
});

test('Cloudflare tools fail with a clear message when no token is set', async () => {
  const r = await callTool('cloudflare_zone', { domain: 'example.com' }, { CLOUDFLARE_API_TOKEN: '' });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /CLOUDFLARE_API_TOKEN/);
});

test('WordPress tool fails clearly when no base URL is set', async () => {
  const r = await callTool('wordpress_rest_index', {}, { WORDPRESS_BASE_URL: '' });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /WORDPRESS_BASE_URL/);
});

test('WooCommerce tool fails clearly when no credentials are set', async () => {
  const r = await callTool('woocommerce_system_status', {}, { WOOCOMMERCE_KEY: '', WOOCOMMERCE_SECRET: '', WOOCOMMERCE_BASE_URL: '' });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /WOOCOMMERCE/);
});

test('Docker tool errors clearly when the docker CLI is unavailable', async () => {
  const messages = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin], { cwd: root, env: { ...process.env, PATH: '/nonexistent' } });
    let buffer = '';
    const out = [];
    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try { out.push(JSON.parse(line)); } catch {}
      }
    });
    child.on('error', reject);
    child.on('close', () => resolve(out));
    child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docker_ps","arguments":{}}}\n');
    child.stdin.end();
  });
  const [resp] = messages;
  assert.equal(resp.result.isError, true);
  assert.match(resp.result.content[0].text, /docker|ENOENT|not found/i);
});
