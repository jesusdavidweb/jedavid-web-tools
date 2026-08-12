// tests/mcp.test.mjs
// Integration tests for the MCP protocol layer: server/discover, initialize,
// tools/list, tools/call, error handling and JSON-RPC envelope shape.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const bin = path.join(root, 'bin', 'jedavid-web-tools-mcp.mjs');

function call(lines, { env = {} } = {}) {
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
    child.stderr.on('data', (chunk) => { /* discard for noise reduction */ });
    child.on('error', reject);
    child.on('close', () => resolve(messages));
    for (const line of lines) child.stdin.write(line + '\n');
    child.stdin.end();
  });
}

test('tools/list returns 54 tools with proper annotations', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}']);
  assert.equal(resp.id, 1);
  assert.equal(resp.jsonrpc, '2.0');
  assert.ok(resp.result.tools);
  assert.equal(resp.result.tools.length, 54);
  for (const tool of resp.result.tools) {
    assert.ok(tool.name);
    assert.ok(tool.title);
    assert.ok(tool.description);
    assert.ok(tool.inputSchema);
    assert.equal(tool.inputSchema.type, 'object');
    assert.ok(tool.annotations);
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.annotations.destructiveHint, false);
    assert.equal(tool.annotations.idempotentHint, true);
    // openWorldHint should be true for network tools, false for docker local.
    if (tool.name.startsWith('docker_')) {
      assert.equal(tool.annotations.openWorldHint, false);
    } else {
      assert.equal(tool.annotations.openWorldHint, true);
    }
  }
});

test('initialize returns the requested protocol version when supported', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}']);
  assert.equal(resp.result.protocolVersion, '2025-11-25');
  assert.equal(resp.result.serverInfo.name, 'jedavid-web-tools');
  assert.ok(resp.result.instructions);
  assert.ok(resp.result.capabilities.tools);
});

test('initialize falls back when an unsupported version is requested', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}']);
  assert.equal(resp.result.protocolVersion, '2025-11-25');
});

test('server/discover returns the modern protocol handshake', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}']);
  assert.equal(resp.result.resultType, 'complete');
  assert.ok(Array.isArray(resp.result.supportedVersions));
  assert.ok(resp.result.supportedVersions.includes('2026-07-28'));
  assert.equal(resp.result.serverInfo.name, 'jedavid-web-tools');
});

test('ping returns an empty object', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"ping"}']);
  assert.deepEqual(resp.result, {});
});

test('unknown method returns a JSON-RPC -32601 error', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"no_such_method"}']);
  assert.equal(resp.error.code, -32601);
  assert.match(resp.error.message, /Method not found/);
});

test('unknown tool returns isError content (not a transport error)', async () => {
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}']);
  assert.ok(resp.result);
  assert.equal(resp.result.isError, true);
  assert.ok(Array.isArray(resp.result.content));
  assert.match(resp.result.content[0].text, /Unknown tool/);
});

test('tools/call with invalid arguments is rejected with validation guidance', async () => {
  // http_inspect requires `url`; omit it and expect a useful error.
  const [resp] = await call(['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_inspect","arguments":{}}}']);
  assert.ok(resp.result);
  assert.equal(resp.result.isError, true);
});

test('a notification (no id) is silently dropped', async () => {
  const messages = await call([
    '{"jsonrpc":"2.0","method":"notifications/some_notification","params":{}}',
    '{"jsonrpc":"2.0","id":99,"method":"ping"}',
  ]);
  // Only the ping response should arrive.
  assert.equal(messages.length, 1);
  assert.equal(messages[0].id, 99);
});

test('invalid JSON line is ignored without crashing', async () => {
  const messages = await call([
    'not json',
    '{"jsonrpc":"2.0","id":1,"method":"ping"}',
  ]);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].id, 1);
});

test('localhost target is blocked by SSRF defense', async () => {
  // For this test we explicitly disable the loopback opt-in so the SSRF
  // defense has to do its job.
  const messages = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin], { cwd: root, env: { ...process.env, JEDAVID_TEST_ALLOW_LOOPBACK: '0' } });
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
    child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_inspect","arguments":{"url":"http://localhost/"}}}\n');
    child.stdin.end();
  });
  const [resp] = messages;
  assert.equal(resp.result.isError, true);
  assert.match(resp.result.content[0].text, /blocked|Localhost/i);
});

test('private IP target is blocked by SSRF defense', async () => {
  const messages = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin], { cwd: root, env: { ...process.env, JEDAVID_TEST_ALLOW_LOOPBACK: '0' } });
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
    child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_inspect","arguments":{"url":"http://10.0.0.1/"}}}\n');
    child.stdin.end();
  });
  const [resp] = messages;
  assert.equal(resp.result.isError, true);
  assert.match(resp.result.content[0].text, /blocked/i);
});

test('AWS metadata endpoint is blocked by SSRF defense', async () => {
  const messages = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin], { cwd: root, env: { ...process.env, JEDAVID_TEST_ALLOW_LOOPBACK: '0' } });
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
    child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_inspect","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}\n');
    child.stdin.end();
  });
  const [resp] = messages;
  assert.equal(resp.result.isError, true);
  assert.match(resp.result.content[0].text, /blocked/i);
});
