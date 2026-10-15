import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../server/index.js';

const adminToken = randomBytes(32).toString('base64url');
const agentToken = randomBytes(32).toString('base64url');
const origin = 'https://vault.example';
const value = 'mcp-test-private-value-123456789';
let app, directory, base, adminCookie, client, transport;

before(async () => {
  await mkdir('/tmp/opencode', { recursive: true });
  directory = await mkdtemp('/tmp/opencode/nod-mcp-test-');
  app = createApp({ encryptionKey: randomBytes(32).toString('base64'), adminToken, agentToken, origin, dataDir: directory });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  base = `http://127.0.0.1:${app.address().port}`;
  const login = await fetch(`${base}/api/auth/login`, {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ token: adminToken }),
  });
  assert.equal(login.status, 200);
  adminCookie = login.headers.get('set-cookie').split(';')[0];
  const create = await fetch(`${base}/api/admin/secrets`, {
    method: 'POST', headers: { Origin: origin, Cookie: adminCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: 'BILLING_KEY', description: 'Test-mode billing API credential', value }),
  });
  assert.equal(create.status, 201);
});
after(async () => {
  await client?.close();
  await new Promise(resolve => app.close(resolve));
  await rm(directory, { recursive: true, force: true });
});

async function rpc(message, options = {}) {
  const headers = {
    'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
    ...(options.auth === null ? {} : { Authorization: `Bearer ${options.auth ?? agentToken}` }),
    ...options.headers,
  };
  const response = await fetch(`${base}/mcp`, {
    method: options.method ?? 'POST', headers,
    body: ['GET', 'DELETE', 'HEAD'].includes(options.method) ? undefined : options.raw ?? JSON.stringify(message),
  });
  const text = await response.text();
  return { response, text, data: text ? JSON.parse(text) : null };
}
const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'nod-test-client', version: '1.0.0' } } };

test('MCP requires the agent bearer token for every HTTP method', async () => {
  for (const method of ['POST', 'GET', 'DELETE']) {
    for (const auth of [null, 'invalid', adminToken]) {
      const result = await rpc(initialize, { auth, method });
      assert.equal(result.response.status, 401);
      assert.equal(result.response.headers.get('www-authenticate'), 'Bearer');
      assert.ok(!result.text.includes(value));
    }
  }
  const cookieOnly = await rpc(initialize, { auth: null, headers: { Cookie: adminCookie } });
  assert.equal(cookieOnly.response.status, 401);
  const queryToken = await fetch(`${base}/mcp?token=${agentToken}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(initialize) });
  assert.equal(queryToken.status, 401);
});

test('MCP rejects foreign browser origins and allows originless tool clients', async () => {
  assert.equal((await rpc(initialize, { headers: { Origin: 'https://evil.example' } })).response.status, 403);
  assert.equal((await rpc(initialize, { headers: { Origin: 'null' } })).response.status, 403);
  assert.equal((await rpc(initialize, { headers: { Origin: origin } })).response.status, 200);
  const result = await rpc(initialize);
  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get('access-control-allow-origin'), null);
});

test('MCP initialize negotiates protocol and advertises only read-only tools', async () => {
  const result = await rpc(initialize);
  assert.equal(result.response.status, 200);
  assert.equal(result.data.jsonrpc, '2.0');
  assert.equal(result.data.id, 1);
  assert.equal(result.data.result.protocolVersion, '2025-11-25');
  assert.equal(result.data.result.serverInfo.name, 'nod-secret-vault');
  assert.ok(result.data.result.capabilities.tools);
  assert.match(result.data.result.instructions, /untrusted/);
  assert.equal(result.response.headers.get('mcp-session-id'), null);
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
  assert.ok(!result.text.includes(value));
});

test('MCP notifications return 202 without a response body', async () => {
  const result = await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(result.response.status, 202);
  assert.equal(result.text, '');
});

test('official MCP client connects over Streamable HTTP and discovers tool schemas', async () => {
  client = new Client({ name: 'nod-sdk-test', version: '1.0.0' });
  transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${agentToken}` } } });
  await client.connect(transport);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(tool => tool.name).sort(), ['get_secret', 'list_keys']);
  for (const tool of tools) {
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.annotations.destructiveHint, false);
    assert.equal(tool.annotations.openWorldHint, false);
    assert.ok(tool.outputSchema);
  }
  assert.deepEqual(tools.find(tool => tool.name === 'get_secret').inputSchema.required, ['key']);
});

test('MCP catalog contains keys and descriptions but never values', async () => {
  const result = await client.callTool({ name: 'list_keys', arguments: {} });
  assert.ok(!result.isError);
  const catalog = JSON.parse(result.content[0].text);
  assert.deepEqual(result.structuredContent, catalog);
  assert.equal(catalog.keys[0].key, 'BILLING_KEY');
  assert.equal(catalog.keys[0].description, 'Test-mode billing API credential');
  assert.deepEqual(Object.keys(catalog.keys[0]).sort(), ['createdAt', 'description', 'key', 'updatedAt']);
  assert.ok(!JSON.stringify(result).includes(value));
});

test('MCP retrieves only the requested secret, with no-cache responses and metadata-only audit', async () => {
  const result = await client.callTool({ name: 'get_secret', arguments: { key: 'BILLING_KEY' } });
  assert.ok(!result.isError);
  assert.deepEqual(result.structuredContent, { key: 'BILLING_KEY', value });
  assert.deepEqual(JSON.parse(result.content[0].text), { key: 'BILLING_KEY', value });
  const raw = await rpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_secret', arguments: { key: 'BILLING_KEY' } } });
  assert.equal(raw.response.headers.get('cache-control'), 'no-store');
  const response = await fetch(`${base}/api/admin/activity`, { headers: { Cookie: adminCookie } });
  const audit = await response.json();
  assert.ok(audit.activity.some(event => event.action === 'catalog.listed' && event.actor === 'agent'));
  assert.ok(audit.activity.some(event => event.action === 'secret.retrieved' && event.key === 'BILLING_KEY' && event.actor === 'agent'));
  assert.ok(!JSON.stringify(audit).includes(value));
});

test('MCP hides disabled secrets and restores access when re-enabled', async () => {
  async function setEnabled(enabled) {
    const response = await fetch(`${base}/api/admin/secrets/BILLING_KEY`, {
      method: 'PUT', headers: { Origin: origin, Cookie: adminCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    assert.equal(response.status, 200);
  }
  await setEnabled(false);
  const catalog = await client.callTool({ name: 'list_keys', arguments: {} });
  assert.deepEqual(catalog.structuredContent.keys, []);
  const denied = await client.callTool({ name: 'get_secret', arguments: { key: 'BILLING_KEY' } });
  assert.equal(denied.isError, true);
  assert.ok(!JSON.stringify(denied).includes(value));
  await setEnabled(true);
  const restored = await client.callTool({ name: 'get_secret', arguments: { key: 'BILLING_KEY' } });
  assert.deepEqual(restored.structuredContent, { key: 'BILLING_KEY', value });
});

test('MCP missing or invalid keys return errors without secret values', async () => {
  for (const key of ['MISSING', '../BILLING_KEY', '', 'x'.repeat(129)]) {
    const result = await client.callTool({ name: 'get_secret', arguments: { key } });
    assert.equal(result.isError, true);
    assert.ok(!JSON.stringify(result).includes(value));
  }
  const missingArgument = await client.callTool({ name: 'get_secret', arguments: {} });
  assert.equal(missingArgument.isError, true);
  const unsupported = await rpc({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'create_secret', arguments: {} } });
  assert.ok(unsupported.data.error || unsupported.data.result?.isError);
});

test('MCP validates transport methods, Accept, content type, and JSON-RPC messages', async () => {
  for (const method of ['GET', 'DELETE', 'PUT']) {
    const result = await rpc(initialize, { method });
    assert.equal(result.response.status, 405);
    assert.equal(result.response.headers.get('allow'), 'POST');
  }
  assert.equal((await rpc(initialize, { headers: { Accept: 'application/json' } })).response.status, 406);
  assert.equal((await rpc(initialize, { headers: { 'Content-Type': 'text/plain' } })).response.status, 415);
  const malformed = await rpc(null, { raw: '{invalid' });
  assert.equal(malformed.response.status, 400);
  assert.equal(malformed.data.error.code, -32700);
  const invalid = await rpc({ method: 'tools/list' });
  assert.equal(invalid.response.status, 400);
  // The SDK treats an invalid JSON-RPC envelope as a protocol parse error.
  assert.equal(invalid.data.error.code, -32700);
  const unsupported = await rpc({ jsonrpc: '2.0', id: 8, method: 'unknown_method' });
  assert.equal(unsupported.data.error.code, -32601);
  // Initialization negotiates its version in params; subsequent requests
  // validate the MCP-Protocol-Version transport header.
  assert.equal((await rpc({ jsonrpc: '2.0', id: 9, method: 'tools/list' }, { headers: { 'MCP-Protocol-Version': '1900-01-01' } })).response.status, 400);
});

test('MCP bounds request bodies and handles errors without leaking sensitive data', async () => {
  const result = await rpc(null, { raw: JSON.stringify({ padding: 'x'.repeat(100_000) }) });
  assert.equal(result.response.status, 413);
  assert.ok(!result.text.includes(value));
});

test('public discovery advertises MCP without credentials or secret metadata', async () => {
  const response = await fetch(`${base}/api/v1`);
  const discovery = await response.json();
  assert.equal(discovery.mcp.url, `${origin}/mcp`);
  assert.deepEqual(discovery.mcp.tools, ['list_keys', 'get_secret']);
  const instructions = await (await fetch(`${base}/llms.txt`)).text();
  assert.ok(instructions.includes(`${origin}/mcp`));
  for (const text of [JSON.stringify(discovery), instructions]) {
    assert.ok(!text.includes(value));
    assert.ok(!text.includes(agentToken));
    assert.ok(!text.includes('BILLING_KEY'));
  }
});

test('MCP masks internal crypto failures instead of exposing raw errors', async () => {
  const db = new DatabaseSync(join(directory, 'vault.sqlite'));
  db.prepare('UPDATE secrets SET encrypted_value = ? WHERE key = ?').run('invalid-ciphertext', 'BILLING_KEY');
  db.close();
  const result = await client.callTool({ name: 'get_secret', arguments: { key: 'BILLING_KEY' } });
  assert.equal(result.isError, true);
  assert.equal(result.content[0].text, 'Unable to retrieve secret.');
  assert.ok(!JSON.stringify(result).includes(value));
  assert.ok(!JSON.stringify(result).includes('invalid-ciphertext'));
});

test('MCP and REST share the agent rate-limit bucket', async () => {
  let limited = false;
  for (let index = 0; index < 121; index++) {
    const result = await rpc(initialize, { auth: 'rate-limit-test-invalid' });
    if (result.response.status === 429) {
      assert.equal(result.response.headers.get('retry-after'), '60');
      limited = true;
      break;
    }
  }
  assert.ok(limited);
  const response = await fetch(`${base}/api/v1/keys`, { headers: { Authorization: `Bearer ${agentToken}` } });
  assert.equal(response.status, 429);
});
