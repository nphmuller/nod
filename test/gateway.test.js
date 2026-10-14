import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { once } from 'node:events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema, McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { createApp } from '../server/index.js';
import { validateUpstream } from '../server/gateway.js';

const agentToken = randomBytes(32).toString('base64url');
const adminToken = randomBytes(32).toString('base64url');
const origin = 'https://nod.gateway.example';
const encryptionKey = randomBytes(32).toString('base64');
let app, base, directory, cookie, downstream;
let upstreamToken = 'upstream-private-token-1234567890';
let secondToken = 'second-private-api-key-0987654321';
let toolCatalog = [{ name: 'echo', description: 'Echo structured arguments.', inputSchema: {
  type: 'object', required: ['payload'], properties: { payload: { $ref: '#/$defs/Payload' } },
  $defs: { Payload: { type: 'object', required: ['message'], properties: { message: { type: 'string' }, flags: { type: 'array', items: { type: 'boolean' } } }, additionalProperties: false } }, additionalProperties: false,
}, outputSchema: { type: 'object', required: ['message'], properties: { message: { type: 'string' } } }, annotations: { readOnlyHint: true, destructiveHint: false } },
{ name: 'mutate', description: 'An external write.', inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: false, destructiveHint: true } },
{ name: 'expose', description: 'Fixture credential echo.', inputSchema: { type: 'object', properties: {} } },
{ name: 'fail', description: 'Fixture transport failure.', inputSchema: { type: 'object', properties: {} } },
{ name: 'slow', description: 'Fixture slow action.', inputSchema: { type: 'object', properties: {} } },
{ name: 'bad/name', description: 'Fixture nonstandard name.', inputSchema: { type: 'object', properties: {} } }];
const fixtures = [];

async function startFixture(header, expected) {
  const sessions = new Map();
  const state = { sessions, initCount: 0, requests: [], calls: [], writes: 0, includeCredentialInCatalog: false, oauthChallenges: 0, paged: false };
  const http = createServer(async (req, res) => {
    state.requests.push({ authorization: req.headers.authorization, apiKey: req.headers['x-api-key'], session: req.headers['mcp-session-id'] });
    if (req.headers[header] !== expected()) {
      state.oauthChallenges++;
      res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer resource_metadata="https://untrusted.invalid/oauth"' });
      res.end(JSON.stringify({ error: `Denied. Fixture private detail: ${expected()}` }));
      return;
    }
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    if (req.method === 'DELETE') {
      const session = sessions.get(req.headers['mcp-session-id']);
      if (session) await session.transport.handleRequest(req, res);
      else { res.writeHead(404); res.end(); }
      return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    let session = sessions.get(req.headers['mcp-session-id']);
    if (body.method === 'initialize') {
      state.initCount++;
      const server = new Server({ name: 'gateway-test-upstream', version: '1.0.0' }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, request => {
        const offset = state.paged ? Number(request.params?.cursor ?? 0) : 0;
        const page = state.paged ? toolCatalog.slice(offset, offset + 2) : toolCatalog;
        return { tools: page.map(tool => ({ ...tool, description: state.includeCredentialInCatalog ? expected() : tool.description })), ...(state.paged && offset + 2 < toolCatalog.length ? { nextCursor: String(offset + 2) } : {}) };
      });
      server.setRequestHandler(CallToolRequestSchema, async request => {
        state.calls.push(request.params);
        const name = request.params.name;
        if (name === 'mutate') { state.writes++; return { content: [{ type: 'text', text: 'Write completed.' }] }; }
        if (name === 'expose') return { content: [{ type: 'text', text: `Authorization was ${expected()}` }] };
        if (name === 'fail') throw new McpError(ErrorCode.InternalError, `Fixture raw error containing ${expected()}`);
        if (name === 'slow') await new Promise(resolve => setTimeout(resolve, 1400));
        const data = { message: request.params.arguments?.payload?.message ?? 'done' };
        return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
      });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: randomUUID, enableJsonResponse: true });
      session = { server, transport };
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      sessions.set(transport.sessionId, session);
      return;
    }
    if (!session) { res.writeHead(404); res.end(); return; }
    await session.transport.handleRequest(req, res, body);
  });
  http.listen(0, '127.0.0.1');
  await once(http, 'listening');
  state.http = http;
  state.url = `http://127.0.0.1:${http.address().port}/mcp`;
  fixtures.push(state);
  return state;
}
let first, second;

before(async () => {
  await mkdir('/tmp/opencode', { recursive: true });
  directory = await mkdtemp('/tmp/opencode/nod-gateway-test-');
  first = await startFixture('authorization', () => `Bearer ${upstreamToken}`);
  second = await startFixture('x-api-key', () => secondToken);
  app = createApp({ encryptionKey, adminToken, agentToken, origin, dataDir: directory });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  base = `http://127.0.0.1:${app.address().port}`;
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ token: adminToken }) });
  assert.equal(login.status, 200);
  cookie = login.headers.get('set-cookie').split(';')[0];
  await admin('/api/admin/secrets', 'POST', { key: 'UPSTREAM_TOKEN', description: 'Upstream bearer credential', value: upstreamToken });
  await admin('/api/admin/secrets', 'POST', { key: 'SECOND_TOKEN', description: 'Custom header credential', value: secondToken });
  downstream = new Client({ name: 'gateway-downstream-test', version: '1.0.0' });
  await downstream.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${agentToken}` } } }));
});

after(async () => {
  await downstream?.close();
  await new Promise(resolve => app.close(resolve));
  for (const fixture of fixtures) {
    for (const { server } of fixture.sessions.values()) await server.close();
    fixture.http.closeAllConnections();
    await new Promise(resolve => fixture.http.close(resolve));
  }
  await rm(directory, { recursive: true, force: true });
});

async function admin(path, method = 'GET', data, headers = {}) {
  const response = await fetch(base + path, { method, headers: { Cookie: cookie, Origin: origin, 'Content-Type': 'application/json', ...headers }, body: data === undefined ? undefined : JSON.stringify(data) });
  const result = await response.json();
  return { status: response.status, data: result, text: JSON.stringify(result) };
}
const serverConfig = (id, url, headers = [], extra = {}) => ({ id, url, headers, enabled: true, allowInsecureHttp: true, timeoutMs: 3000, ...extra });

test('gateway configuration requires an admin session and trusted mutation origin', async () => {
  const response = await fetch(base + '/api/admin/mcp-servers', { headers: { Authorization: `Bearer ${agentToken}` } });
  assert.equal(response.status, 401);
  const result = await admin('/api/admin/mcp-servers', 'POST', serverConfig('unauthorized', first.url), { Origin: 'https://evil.example' });
  assert.equal(result.status, 403);
});

test('gateway validates remote-only configuration, TLS opt-in, and credential references', () => {
  const valid = serverConfig('home_assistant', first.url, [{ name: 'Authorization', secretKey: 'UPSTREAM_TOKEN', prefix: 'Bearer ' }]);
  assert.equal(validateUpstream(valid, origin).id, 'home_assistant');
  const invalid = [
    { ...valid, id: 'Bad-ID' }, { ...valid, id: 'a__b' }, { ...valid, id: 'a_' }, { ...valid, type: 'local', command: ['sh'] },
    { ...valid, oauth: true }, { ...valid, allowInsecureHttp: false },
    { ...valid, url: 'file:///etc/passwd' }, { ...valid, url: 'https://user:password@example.com/mcp' },
    { ...valid, url: 'https://example.com/mcp?token=private' }, { ...valid, url: origin + '/mcp/' },
    { ...valid, timeoutMs: 0 }, { ...valid, enabled: 'true' },
    { ...valid, headers: [{ name: 'Authorization', value: upstreamToken }] },
    { ...valid, headers: [{ name: 'Host', secretKey: 'UPSTREAM_TOKEN' }] },
    { ...valid, headers: [{ name: 'MCP-Session-Id', secretKey: 'UPSTREAM_TOKEN' }] },
    { ...valid, headers: [{ name: 'X\r\nBad', secretKey: 'UPSTREAM_TOKEN' }] },
    { ...valid, headers: [{ name: 'Authorization', secretKey: 'UPSTREAM_TOKEN', prefix: 'Bearer\n' }] },
    { ...valid, headers: [{ name: 'X-Api-Key', secretKey: 'UPSTREAM_TOKEN' }, { name: 'x-api-key', secretKey: 'SECOND_TOKEN' }] },
  ];
  for (const config of invalid) assert.throws(() => validateUpstream(config, origin), error => error.status === 400);
});

test('admin adds bearer and custom-header upstreams without exposing credential values', async () => {
  const firstResult = await admin('/api/admin/mcp-servers', 'POST', serverConfig('home_assistant', first.url, [{ name: 'Authorization', secretKey: 'UPSTREAM_TOKEN', prefix: 'Bearer ' }]));
  assert.equal(firstResult.status, 201);
  assert.equal(firstResult.data.status, 'connected');
  assert.equal(firstResult.data.toolCount, toolCatalog.length);
  const secondResult = await admin('/api/admin/mcp-servers', 'POST', serverConfig('other', second.url, [{ name: 'X-Api-Key', secretKey: 'SECOND_TOKEN' }]));
  assert.equal(secondResult.data.status, 'connected');
  for (const result of [firstResult, secondResult, await admin('/api/admin/mcp-servers')]) {
    assert.ok(!result.text.includes(upstreamToken));
    assert.ok(!result.text.includes(secondToken));
  }
  const db = await readFile(join(directory, 'vault.sqlite'));
  assert.ok(!db.includes(Buffer.from(upstreamToken)));
  assert.ok(!db.includes(Buffer.from(secondToken)));
  assert.equal((await admin('/api/admin/mcp-servers', 'POST', serverConfig('other', second.url))).status, 409);
});

test('gateway preserves built-ins, arbitrary JSON Schemas, namespaces, and upstream mutation annotations', async () => {
  const { tools } = await downstream.listTools();
  assert.ok(tools.some(tool => tool.name === 'list_keys'));
  assert.ok(tools.some(tool => tool.name === 'get_secret'));
  const echo = tools.find(tool => tool.name === 'home_assistant__echo');
  assert.deepEqual(echo.inputSchema, toolCatalog[0].inputSchema);
  assert.deepEqual(echo.outputSchema, toolCatalog[0].outputSchema);
  assert.equal(echo.annotations.readOnlyHint, true);
  assert.equal(tools.find(tool => tool.name === 'home_assistant__mutate').annotations.readOnlyHint, false);
  assert.equal(tools.find(tool => tool.name === 'home_assistant__mutate').annotations.destructiveHint, true);
  assert.ok(tools.some(tool => tool.name === 'other__echo'));
  const sanitized = tools.find(tool => tool.name.startsWith('home_assistant__bad_name_'));
  assert.ok(sanitized && sanitized.name.length <= 128);
  assert.ok(!JSON.stringify(tools).includes(upstreamToken));
});

test('gateway forwards arguments and structured results while retaining upstream sessions', async () => {
  const initializations = first.initCount;
  const args = { payload: { message: 'hello through Nod', flags: [true, false] } };
  const result = await downstream.callTool({ name: 'home_assistant__echo', arguments: args });
  assert.deepEqual(result.structuredContent, { message: 'hello through Nod' });
  assert.deepEqual(first.calls.at(-1).arguments, args);
  const write = await downstream.callTool({ name: 'home_assistant__mutate', arguments: {} });
  assert.ok(!write.isError);
  assert.equal(first.writes, 1);
  assert.equal(first.initCount, initializations);
  assert.ok(first.requests.some(request => request.session));
  assert.ok(first.requests.every(request => request.authorization === `Bearer ${upstreamToken}`));
  assert.ok(first.requests.every(request => request.authorization !== `Bearer ${agentToken}`));
  const custom = await downstream.callTool({ name: 'other__echo', arguments: args });
  assert.equal(custom.structuredContent.message, 'hello through Nod');
  assert.ok(second.requests.every(request => request.apiKey === secondToken && !request.authorization));
});

test('gateway withholds echoed credentials and masks upstream exception details', async () => {
  for (const tool of ['expose', 'fail']) {
    const result = await downstream.callTool({ name: `home_assistant__${tool}`, arguments: {} });
    assert.equal(result.isError, true);
    assert.ok(!JSON.stringify(result).includes(upstreamToken));
    assert.ok(!JSON.stringify(result).includes('Fixture raw error'));
  }
  const activity = await admin('/api/admin/activity');
  assert.ok(activity.data.activity.some(event => event.action === 'gateway.tool_called' && event.key === 'home_assistant__echo'));
  assert.ok(!activity.text.includes(upstreamToken));
  assert.ok(!activity.text.includes('hello through Nod'));
});

test('secret rotation reconnects upstreams without restarting Nod or exposing tokens', async () => {
  const before = first.initCount;
  upstreamToken = 'rotated-upstream-private-token-33333333';
  assert.equal((await admin('/api/admin/secrets/UPSTREAM_TOKEN', 'PUT', { description: 'Rotated credential', value: upstreamToken })).status, 200);
  const result = await downstream.callTool({ name: 'home_assistant__echo', arguments: { payload: { message: 'after rotation' } } });
  assert.equal(result.structuredContent.message, 'after rotation');
  assert.ok(first.initCount > before);
  const native = await downstream.callTool({ name: 'get_secret', arguments: { key: 'UPSTREAM_TOKEN' } });
  assert.equal(native.structuredContent.value, upstreamToken);
  const rest = await fetch(base + '/api/v1/keys/UPSTREAM_TOKEN/value', { headers: { Authorization: `Bearer ${agentToken}` } });
  assert.equal((await rest.json()).value, upstreamToken);
});

test('server disable, re-enable, reconnect, removal, and key deletion update the tool catalog', async () => {
  let servers = (await admin('/api/admin/mcp-servers')).data.servers;
  const other = servers.find(server => server.id === 'other');
  const config = serverConfig(other.id, other.url, other.headers, { enabled: false });
  assert.equal((await admin('/api/admin/mcp-servers/other', 'PUT', config)).data.status, 'disabled');
  assert.ok(!(await downstream.listTools()).tools.some(tool => tool.name.startsWith('other__')));
  assert.equal((await downstream.callTool({ name: 'other__echo', arguments: {} })).isError, true);
  assert.equal((await admin('/api/admin/mcp-servers/other', 'PUT', { ...config, enabled: true })).data.status, 'connected');
  toolCatalog = [...toolCatalog, { name: 'added_later', description: 'New fixture tool.', inputSchema: { type: 'object', properties: {} } }];
  await admin('/api/admin/mcp-servers/other/reconnect', 'POST');
  assert.ok((await downstream.listTools()).tools.some(tool => tool.name === 'other__added_later'));
  await admin('/api/admin/secrets/SECOND_TOKEN', 'DELETE');
  servers = (await admin('/api/admin/mcp-servers')).data.servers;
  assert.equal(servers.find(server => server.id === 'other').status, 'failed');
  assert.ok(!(await downstream.listTools()).tools.some(tool => tool.name.startsWith('other__')));
  await admin('/api/admin/mcp-servers/other', 'DELETE');
  assert.ok(!(await admin('/api/admin/mcp-servers')).data.servers.some(server => server.id === 'other'));
  assert.ok((await admin('/api/admin/secrets')).data.keys.some(key => key.key === 'UPSTREAM_TOKEN'));
});

test('failed authentication and missing credentials do not hide Nod tools or leak raw errors', async () => {
  await admin('/api/admin/secrets', 'POST', { key: 'WRONG_TOKEN', description: 'Wrong test credential', value: 'wrong-private-test-token-111111' });
  const denied = await admin('/api/admin/mcp-servers', 'POST', serverConfig('denied', first.url, [{ name: 'Authorization', secretKey: 'WRONG_TOKEN', prefix: 'Bearer ' }]));
  assert.equal(denied.data.status, 'failed');
  assert.ok(!denied.text.includes(upstreamToken));
  assert.ok(!denied.text.includes('Fixture private detail'));
  const missing = await admin('/api/admin/mcp-servers', 'POST', serverConfig('missing', first.url, [{ name: 'Authorization', secretKey: 'DOES_NOT_EXIST' }]));
  assert.equal(missing.data.status, 'failed');
  const { tools } = await downstream.listTools();
  assert.ok(tools.some(tool => tool.name === 'list_keys'));
  assert.ok(!tools.some(tool => tool.name.startsWith('denied__') || tool.name.startsWith('missing__')));
  assert.equal((await downstream.callTool({ name: 'denied__echo', arguments: {} })).isError, true);
});

test('connection catalog credential echoes are withheld and manual reconnect recovers', async () => {
  first.includeCredentialInCatalog = true;
  const failed = await admin('/api/admin/mcp-servers/home_assistant/reconnect', 'POST');
  assert.equal(failed.data.status, 'failed');
  assert.ok(!failed.text.includes(upstreamToken));
  first.includeCredentialInCatalog = false;
  assert.equal((await admin('/api/admin/mcp-servers/home_assistant/reconnect', 'POST')).data.status, 'connected');
});

test('gateway handles paginated catalogs and shares a new connection across concurrent calls', async () => {
  first.paged = true;
  const reconnect = await admin('/api/admin/mcp-servers/home_assistant/reconnect', 'POST');
  assert.equal(reconnect.data.toolCount, toolCatalog.length);
  first.paged = false;
  const before = first.initCount;
  upstreamToken = 'concurrent-rotation-private-token-44444444';
  await admin('/api/admin/secrets/UPSTREAM_TOKEN', 'PUT', { description: 'Concurrent reconnect test', value: upstreamToken });
  const results = await Promise.all(['one', 'two', 'three'].map(message => downstream.callTool({ name: 'home_assistant__echo', arguments: { payload: { message } } })));
  assert.deepEqual(results.map(result => result.structuredContent.message), ['one', 'two', 'three']);
  assert.equal(first.initCount, before + 1);
});

test('creating a formerly missing credential restores its upstream immediately', async () => {
  await admin('/api/admin/secrets', 'POST', { key: 'DOES_NOT_EXIST', description: 'Repaired missing reference', value: 'Bearer ' + upstreamToken });
  const status = (await admin('/api/admin/mcp-servers')).data.servers.find(server => server.id === 'missing');
  assert.equal(status.status, 'connected');
  assert.ok((await downstream.listTools()).tools.some(tool => tool.name === 'missing__echo'));
  await admin('/api/admin/mcp-servers/missing', 'DELETE');
});

test('gateway rejects aliases pointing back to Nod before recursive tool discovery', async () => {
  await admin('/api/admin/secrets', 'POST', { key: 'SELF_GATEWAY_TOKEN', description: 'Temporary loop test credential', value: agentToken });
  const result = await admin('/api/admin/mcp-servers', 'POST', serverConfig('self_alias', base + '/mcp', [{ name: 'Authorization', secretKey: 'SELF_GATEWAY_TOKEN', prefix: 'Bearer ' }]));
  assert.equal(result.data.status, 'failed');
  assert.ok(!result.text.includes(agentToken));
  await admin('/api/admin/mcp-servers/self_alias', 'DELETE');
  await admin('/api/admin/secrets/SELF_GATEWAY_TOKEN', 'DELETE');
});

test('gateway timeouts are bounded and mutating calls are never automatically retried', async () => {
  const server = (await admin('/api/admin/mcp-servers')).data.servers.find(server => server.id === 'home_assistant');
  await admin('/api/admin/mcp-servers/home_assistant', 'PUT', serverConfig(server.id, server.url, server.headers, { timeoutMs: 1000 }));
  const before = first.calls.filter(call => call.name === 'slow').length;
  const result = await downstream.callTool({ name: 'home_assistant__slow', arguments: {} });
  assert.equal(result.isError, true);
  assert.ok(!JSON.stringify(result).includes(upstreamToken));
  assert.equal(first.calls.filter(call => call.name === 'slow').length, before + 1);
});

test('gateway refuses redirected endpoints without forwarding credentials', async () => {
  let redirectedRequests = 0;
  const target = createServer((req, res) => { redirectedRequests++; res.end('unexpected'); });
  target.listen(0, '127.0.0.1'); await once(target, 'listening');
  const redirect = createServer((req, res) => { res.writeHead(307, { Location: `http://127.0.0.1:${target.address().port}/mcp` }); res.end(); });
  redirect.listen(0, '127.0.0.1'); await once(redirect, 'listening');
  try {
    const result = await admin('/api/admin/mcp-servers', 'POST', serverConfig('redirected', `http://127.0.0.1:${redirect.address().port}/mcp`, [{ name: 'Authorization', secretKey: 'UPSTREAM_TOKEN', prefix: 'Bearer ' }]));
    assert.equal(result.data.status, 'failed');
    assert.equal(redirectedRequests, 0);
  } finally {
    target.closeAllConnections(); redirect.closeAllConnections();
    await Promise.all([new Promise(resolve => target.close(resolve)), new Promise(resolve => redirect.close(resolve))]);
  }
});

test('upstream configurations persist across Nod restarts; discovery never exposes them', async () => {
  const publicResponse = await fetch(base + '/api/v1');
  const publicInfo = await publicResponse.json();
  assert.equal(publicInfo.mcp.gateway.supportedTransport, 'remote-streamable-http');
  const text = JSON.stringify(publicInfo);
  assert.ok(!text.includes(first.url));
  assert.ok(!text.includes('UPSTREAM_TOKEN'));
  assert.ok(!text.includes(upstreamToken));
  await downstream.close();
  await new Promise(resolve => app.close(resolve));
  app = createApp({ encryptionKey, adminToken, agentToken, origin, dataDir: directory });
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  base = `http://127.0.0.1:${app.address().port}`;
  const login = await fetch(base + '/api/auth/login', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ token: adminToken }) });
  cookie = login.headers.get('set-cookie').split(';')[0];
  const server = (await admin('/api/admin/mcp-servers')).data.servers.find(server => server.id === 'home_assistant');
  assert.equal(server.status, 'connected');
  assert.equal(server.headers[0].secretKey, 'UPSTREAM_TOKEN');
});
