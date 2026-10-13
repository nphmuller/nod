import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { once } from 'node:events';
import { createApp } from '../server/index.js';
import { createStore } from '../server/store.js';

const encryptionKey = randomBytes(32).toString('base64');
const adminToken = randomBytes(32).toString('base64url');
const agentToken = randomBytes(32).toString('base64url');
const origin = 'http://localhost:3000';
let directory, app, base, cookie;
const secret = 'test-private-value-do-not-disclose-123';

before(async () => {
  await mkdir('/tmp/opencode', { recursive: true });
  directory = await mkdtemp('/tmp/opencode/nod-test-');
  app = createApp({ encryptionKey, adminToken, agentToken, origin, dataDir: directory });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  base = `http://127.0.0.1:${app.address().port}`;
});
after(async () => {
  await new Promise(resolve => app.close(resolve));
  await rm(directory, { recursive: true, force: true });
});

async function request(path, { method = 'GET', data, auth, session = false, requestOrigin = origin } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth) headers.Authorization = `Bearer ${auth}`;
  if (session) headers.Cookie = cookie;
  if (requestOrigin) headers.Origin = requestOrigin;
  const response = await fetch(`${base}${path}`, { method, headers, body: data === undefined ? undefined : JSON.stringify(data) });
  const text = await response.text();
  return { response, text, data: response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : text };
}

test('public discovery describes authenticated read-only APIs and leaks no keys or credentials', async () => {
  const schema = await request('/openapi.json');
  assert.equal(schema.response.status, 200);
  assert.equal(schema.data.openapi, '3.1.0');
  assert.equal(schema.data.paths['/api/v1/keys'].get.operationId, 'listSecretKeys');
  assert.equal(schema.data.paths['/api/v1/keys/{key}/value'].get.operationId, 'getSecretValue');
  assert.equal(schema.data.components.securitySchemes.bearerAuth.scheme, 'bearer');
  assert.equal(Object.keys(schema.data.paths).length, 2);
  for (const path of ['/api/v1', '/llms.txt', '/.well-known/ai-plugin.json', '/docs', '/']) {
    const result = await request(path);
    assert.equal(result.response.status, 200, path);
    assert.ok(!result.text.includes(agentToken));
    assert.ok(!result.text.includes(adminToken));
  }
});

test('agent endpoints reject missing, wrong, and admin credentials', async () => {
  for (const auth of [undefined, 'invalid', adminToken]) {
    const result = await request('/api/v1/keys', { auth });
    assert.equal(result.response.status, 401);
    assert.equal(result.response.headers.get('www-authenticate'), 'Bearer');
  }
  assert.equal((await request('/api/admin/secrets', { auth: agentToken })).response.status, 401);
});

test('admin login uses an HttpOnly SameSite session and rejects foreign origins', async () => {
  assert.equal((await request('/api/auth/login', { method: 'POST', data: { token: adminToken }, requestOrigin: 'https://evil.example' })).response.status, 403);
  assert.equal((await request('/api/auth/login', { method: 'POST', data: { token: agentToken } })).response.status, 401);
  const login = await request('/api/auth/login', { method: 'POST', data: { token: adminToken } });
  assert.equal(login.response.status, 200);
  const fullCookie = login.response.headers.get('set-cookie');
  assert.match(fullCookie, /HttpOnly/);
  assert.match(fullCookie, /SameSite=Strict/);
  cookie = fullCookie.split(';')[0];
  assert.equal((await request('/api/auth/session', { session: true })).response.status, 200);
});

test('admin creates an encrypted secret, catalog excludes its value, agent explicitly retrieves it', async () => {
  const create = await request('/api/admin/secrets', { method: 'POST', session: true, data: { key: 'STRIPE_API_KEY', description: 'Stripe sandbox billing credential', value: secret } });
  assert.equal(create.response.status, 201);
  assert.ok(!create.text.includes(secret));
  const catalog = await request('/api/v1/keys', { auth: agentToken });
  assert.equal(catalog.response.status, 200);
  assert.equal(catalog.data.keys[0].key, 'STRIPE_API_KEY');
  assert.equal(catalog.data.keys[0].description, 'Stripe sandbox billing credential');
  assert.deepEqual(Object.keys(catalog.data.keys[0]).sort(), ['createdAt', 'description', 'key', 'updatedAt']);
  assert.ok(!catalog.text.includes(secret));
  const database = await readFile(join(directory, 'vault.sqlite'));
  assert.ok(!database.includes(Buffer.from(secret)), 'database must not contain plaintext secret values');
  const value = await request('/api/v1/keys/STRIPE_API_KEY/value', { auth: agentToken });
  assert.equal(value.response.status, 200);
  assert.deepEqual(value.data, { key: 'STRIPE_API_KEY', value: secret });
  assert.equal(value.response.headers.get('cache-control'), 'no-store');
  assert.equal(value.response.headers.get('access-control-allow-origin'), null);
});

test('admin can update metadata without reading or replacing the secret', async () => {
  const update = await request('/api/admin/secrets/STRIPE_API_KEY', { method: 'PUT', session: true, data: { description: 'Updated billing credential' } });
  assert.equal(update.response.status, 200);
  assert.equal(update.data.description, 'Updated billing credential');
  assert.ok(!update.text.includes(secret));
  const value = await request('/api/v1/keys/STRIPE_API_KEY/value', { auth: agentToken });
  assert.equal(value.data.value, secret);
});

test('mutation validation, duplicate protection, CSRF protection, and read-only agent boundary', async () => {
  assert.equal((await request('/api/admin/secrets', { method: 'POST', session: true, data: { key: 'STRIPE_API_KEY', description: 'Duplicate', value: 'other' } })).response.status, 409);
  for (const data of [
    { key: '../invalid', description: 'test', value: 'secret' },
    { key: 'VALID', description: ' ', value: 'secret' },
    { key: 'VALID', description: 'test', value: '' },
    { key: 'VALID', description: 'test' },
    { key: 'VALID', description: 'test', value: 'x'.repeat(65537) },
  ]) assert.equal((await request('/api/admin/secrets', { method: 'POST', session: true, data })).response.status, 400);
  assert.equal((await request('/api/admin/secrets/STRIPE_API_KEY', { method: 'DELETE', session: true, requestOrigin: 'https://evil.example' })).response.status, 403);
  assert.equal((await request('/api/admin/secrets/STRIPE_API_KEY', { method: 'DELETE', session: true, requestOrigin: null })).response.status, 403);
  assert.equal((await request('/api/v1/keys', { method: 'POST', auth: agentToken, data: { key: 'EVIL' } })).response.status, 404);
  assert.equal((await request('/api/v1/keys/MISSING/value', { auth: agentToken })).response.status, 404);
  assert.equal((await request('/api/v1/keys/%ZZ/value', { auth: agentToken })).response.status, 400);
  assert.equal((await request('/api/v1/keys/%3Cscript%3E/value', { auth: agentToken })).response.status, 400);
  assert.equal((await request('/api/v1/keys', { session: true })).response.status, 401);
});

test('secret values can be rotated, audit contains metadata only, and deletion revokes retrieval', async () => {
  const replacement = 'rotated-private-value';
  const update = await request('/api/admin/secrets/STRIPE_API_KEY', { method: 'PUT', session: true, data: { description: 'Rotated credential', value: replacement } });
  assert.equal(update.response.status, 200);
  assert.equal((await request('/api/v1/keys/STRIPE_API_KEY/value', { auth: agentToken })).data.value, replacement);
  const audit = await request('/api/admin/activity', { session: true });
  assert.ok(audit.data.activity.some(event => event.action === 'secret.retrieved' && event.actor === 'agent'));
  assert.ok(audit.data.activity.some(event => event.action === 'secret.updated'));
  assert.ok(!audit.text.includes(secret));
  assert.ok(!audit.text.includes(replacement));
  assert.equal((await request('/api/admin/secrets/STRIPE_API_KEY', { method: 'DELETE', session: true })).response.status, 200);
  assert.equal((await request('/api/v1/keys/STRIPE_API_KEY/value', { auth: agentToken })).response.status, 404);
  assert.deepEqual((await request('/api/v1/keys', { auth: agentToken })).data.keys, []);
});

test('logout invalidates the session', async () => {
  assert.equal((await request('/api/auth/logout', { method: 'POST', session: true })).response.status, 200);
  assert.equal((await request('/api/auth/session', { session: true })).response.status, 401);
});

test('security headers, static allowlist, and JSON content type enforcement', async () => {
  const result = await request('/');
  assert.equal(result.response.headers.get('x-frame-options'), 'DENY');
  assert.match(result.response.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal((await request('/.env')).response.status, 404);
  assert.equal((await request('/server/store.js')).response.status, 404);
  const response = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(response.status, 415);
});

test('rate limits protect agent access and login attempts', async () => {
  let agentLimited = false;
  for (let i = 0; i < 121; i++) {
    // Failed auth is rate-limited too; avoid disk audit writes so this test
    // stays within one rate-limit window even on slow filesystems.
    const result = await request('/api/v1/keys', { auth: 'invalid-rate-limit-test' });
    if (result.response.status === 429) {
      assert.equal(result.response.headers.get('retry-after'), '60');
      agentLimited = true;
      break;
    }
  }
  assert.ok(agentLimited);
  let loginLimited = false;
  for (let i = 0; i < 11; i++) {
    const result = await request('/api/auth/login', { method: 'POST', data: { token: 'invalid' } });
    if (result.response.status === 429) { loginLimited = true; break; }
  }
  assert.ok(loginLimited);
});

test('encrypted data persists across restarts and authenticates against the encryption key', async () => {
  const folder = join(directory, 'persistence');
  const key = Buffer.from(encryptionKey, 'base64');
  let store = createStore(folder, key);
  store.save('PERSISTED', 'Persistent test credential', secret);
  store.close();
  store = createStore(folder, key);
  assert.equal(store.value('PERSISTED'), secret);
  store.close();
  const wrongKeyStore = createStore(folder, randomBytes(32));
  assert.throws(() => wrongKeyStore.value('PERSISTED'));
  wrongKeyStore.close();
});

test('unsafe configuration fails closed', () => {
  assert.throws(() => createApp({ encryptionKey: 'bad', adminToken, agentToken, origin, dataDir: directory }), /Configure/);
  assert.throws(() => createApp({ encryptionKey, adminToken, agentToken: adminToken, origin, dataDir: directory }), /Configure/);
});
