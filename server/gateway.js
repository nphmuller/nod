import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

const idPattern = /^[a-z][a-z0-9_]{0,31}$/;
const keyPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const headerPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const forbiddenHeaders = new Set(['host', 'content-length', 'cookie', 'origin', 'referer', 'connection', 'upgrade', 'transfer-encoding', 'accept', 'content-type', 'mcp-session-id', 'mcp-protocol-version']);
const hash = value => createHash('sha256').update(value).digest('hex');
const toolError = message => ({ isError: true, content: [{ type: 'text', text: message }] });
const maxResponseBytes = 4 * 1024 * 1024;

export function validateUpstream(data, publicOrigin) {
  function invalid(message) { throw Object.assign(new Error(message), { status: 400 }); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) invalid('Expected an MCP server configuration.');
  const allowed = new Set(['id', 'url', 'enabled', 'timeoutMs', 'allowInsecureHttp', 'headers']);
  if (Object.keys(data).some(key => !allowed.has(key))) invalid('Only remote Streamable HTTP servers with secret-reference headers are supported. OAuth, stdio, and inline credentials are not supported.');
  if (typeof data.id !== 'string' || !idPattern.test(data.id) || data.id.includes('__') || data.id.endsWith('_')) invalid('Server ID must start with a lowercase letter, use up to 32 lowercase letters/numbers/single underscores, and not end with an underscore.');
  if (data.enabled !== undefined && typeof data.enabled !== 'boolean') invalid('Enabled must be a boolean.');
  if (data.allowInsecureHttp !== undefined && typeof data.allowInsecureHttp !== 'boolean') invalid('Allow insecure HTTP must be a boolean.');
  const timeoutMs = data.timeoutMs ?? 15000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60000) invalid('Timeout must be between 1000 and 60000 milliseconds.');
  let url;
  try { url = new URL(data.url); } catch { invalid('Enter an absolute HTTP(S) MCP endpoint URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash || url.search || url.href.length > 2048) invalid('Use an HTTP(S) endpoint without credentials, query parameters, or fragments. Put credentials in vault-referenced headers.');
  if (url.protocol === 'http:' && !data.allowInsecureHttp) invalid('HTTPS is required unless you explicitly allow insecure HTTP for a trusted network.');
  if (url.origin === publicOrigin && url.pathname.replace(/\/$/, '') === '/mcp') invalid('Nod cannot use its own MCP endpoint as an upstream.');
  const inputHeaders = data.headers ?? [];
  if (!Array.isArray(inputHeaders) || inputHeaders.length > 16) invalid('Use at most 16 credential headers.');
  const names = new Set();
  const headers = inputHeaders.map(header => {
    if (!header || typeof header !== 'object' || Array.isArray(header) || Object.keys(header).some(key => !['name', 'secretKey', 'prefix'].includes(key))) invalid('Each header must contain name, secretKey, and an optional prefix; no raw values.');
    const name = header.name;
    if (typeof name !== 'string' || name.length > 128 || !headerPattern.test(name) || forbiddenHeaders.has(name.toLowerCase()) || name.toLowerCase().startsWith('proxy-')) invalid('Invalid or reserved HTTP header name.');
    if (names.has(name.toLowerCase())) invalid('Header names must be unique (case-insensitive).');
    names.add(name.toLowerCase());
    if (typeof header.secretKey !== 'string' || !keyPattern.test(header.secretKey)) invalid('Each credential header must reference a valid vault key.');
    const prefix = header.prefix ?? '';
    if (typeof prefix !== 'string' || prefix.length > 128 || /[^\x20-\x7e]/.test(prefix)) invalid('Header prefixes must be printable ASCII, up to 128 characters.');
    return { name, secretKey: header.secretKey, prefix };
  });
  return { id: data.id, url: url.href, enabled: data.enabled ?? true, timeoutMs, allowInsecureHttp: data.allowInsecureHttp ?? false, headers };
}

function namespacedName(id, name) {
  const prefix = `${id}__`;
  if (/^[A-Za-z0-9_.-]+$/.test(name) && prefix.length + name.length <= 128) return prefix + name;
  return prefix + name.replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 128 - prefix.length - 13) + '_' + hash(name).slice(0, 12);
}

// Bound streamed responses as well as JSON, and never follow an HTTP redirect
// with authentication headers. Private LAN endpoints are deliberately allowed:
// only authenticated admins may configure these trusted outbound destinations.
function restrictedFetch(endpoint) {
  return async (input, init = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (url.origin !== endpoint.origin || url.pathname !== endpoint.pathname || url.search) throw new Error('Upstream destination changed.');
    const response = await fetch(input, { ...init, redirect: 'error' });
    if (Number(response.headers.get('content-length')) > maxResponseBytes) {
      await response.body?.cancel();
      throw new Error('Upstream response too large.');
    }
    if (!response.body) return response;
    let size = 0;
    const body = response.body.pipeThrough(new TransformStream({
      transform(chunk, controller) {
        size += chunk.byteLength;
        if (size > maxResponseBytes) { controller.error(new Error('Upstream response too large.')); return; }
        controller.enqueue(chunk);
      },
    }));
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
}

export function createGateway(store, { publicOrigin, protectedValues = [] }) {
  const entries = new Map();
  let closed = false;

  function invalidate(id) {
    const entry = entries.get(id);
    if (!entry) return;
    entries.delete(id);
    entry.disposed = true;
    entry.abort.abort();
    void entry.client?.close().catch(() => {});
  }

  function resolveCredentials(server) {
    const headers = {};
    const credentials = [...protectedValues];
    for (const header of server.headers) {
      const value = store.value(header.secretKey);
      if (value === undefined) throw new Error('missing');
      if (!value || /[^\x20-\x7e]/.test(value)) throw new Error('invalid');
      headers[header.name] = header.prefix + value;
      credentials.push(value, header.prefix + value);
    }
    if (credentials.some(value => value && server.url.includes(value))) throw new Error('invalid');
    return { headers, credentials: credentials.filter(Boolean) };
  }

  function containsCredential(data, credentials) {
    const text = JSON.stringify(data);
    // Also check the JSON-escaped form, so escaping cannot bypass protection.
    return credentials.some(value => text.includes(value) || text.includes(JSON.stringify(value).slice(1, -1)));
  }

  async function open(entry, server, resolved) {
    const client = new Client({ name: 'nod-mcp-gateway', version: '1.0.0' });
    entry.client = client;
    client.onerror = () => {}; // Never log raw upstream errors or headers.
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      if (entries.get(server.id) === entry) invalidate(server.id);
    });
    client.onclose = () => { if (!entry.disposed) { entry.status = 'failed'; entry.error = 'Upstream disconnected. Reconnect or try again shortly.'; entry.retryAt = Date.now() + 5000; } };
    const transport = new StreamableHTTPClientTransport(new URL(server.url), {
      requestInit: { headers: resolved.headers },
      fetch: restrictedFetch(new URL(server.url)),
      // No authProvider: OAuth discovery and browser login are not enabled.
    });
    const discoverySignal = AbortSignal.any([entry.abort.signal, AbortSignal.timeout(server.timeoutMs)]);
    try {
      await client.connect(transport, { timeout: server.timeoutMs, maxTotalTimeout: server.timeoutMs, signal: discoverySignal });
      const tools = new Map();
      let cursor;
      const seen = new Set();
      if (client.getServerVersion()?.name === 'nod-secret-vault') throw new Error('Nod gateway chaining is not supported.');
      if (client.getServerCapabilities()?.tools) {
        do {
          const page = await client.listTools(cursor ? { cursor } : {}, { timeout: server.timeoutMs, maxTotalTimeout: server.timeoutMs, signal: discoverySignal });
          if (containsCredential(page, resolved.credentials)) throw new Error('Credential exposed by upstream catalog.');
          for (const tool of page.tools) {
            const name = namespacedName(server.id, tool.name);
            if (tools.has(name) || tools.size >= 1000) throw new Error('Invalid or oversized upstream tool catalog.');
            tools.set(name, { original: tool.name, tool: {
              ...tool, name, description: `[${server.id}] ${tool.description ?? tool.name}`,
              // Upstreams may perform writes. Do not label every proxy tool as
              // read-only just because Nod's own credential tools are read-only.
              annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true, ...tool.annotations },
            } });
          }
          cursor = page.nextCursor;
          if (cursor && (seen.has(cursor) || seen.size >= 32)) throw new Error('Invalid upstream pagination.');
          if (cursor) seen.add(cursor);
        } while (cursor);
      }
      if (entry.disposed) throw new Error('Connection replaced.');
      entry.tools = tools;
      entry.status = 'connected';
      entry.error = null;
      entry.connectedAt = new Date().toISOString();
    } catch {
      await client.close().catch(() => {});
      entry.status = 'failed';
      entry.error = 'Unable to connect or discover tools. Check the URL, credential keys, and upstream authentication; OAuth and stdio are unsupported.';
      entry.retryAt = Date.now() + 5000;
    }
    return entry;
  }

  async function ensure(server) {
    if (closed) return { status: 'failed', error: 'Gateway is shutting down.', tools: new Map() };
    if (!server.enabled) { invalidate(server.id); return { status: 'disabled', error: null, tools: new Map() }; }
    let resolved;
    try { resolved = resolveCredentials(server); }
    catch {
      invalidate(server.id);
      return { status: 'failed', error: 'A referenced credential is missing, unreadable, or unsuitable for an HTTP header.', tools: new Map() };
    }
    const signature = hash(JSON.stringify({ server, headers: resolved.headers }));
    let entry = entries.get(server.id);
    if (entry && entry.signature === signature && !(entry.status === 'failed' && Date.now() >= entry.retryAt)) {
      return await entry.promise;
    }
    invalidate(server.id);
    entry = { signature, status: 'connecting', error: null, tools: new Map(), abort: new AbortController(), disposed: false, credentials: resolved.credentials };
    entries.set(server.id, entry);
    entry.promise = open(entry, server, resolved);
    return await entry.promise;
  }

  async function describe(server) {
    const entry = await ensure(server);
    return { ...server, status: entry.status, error: entry.error, toolCount: entry.status === 'connected' ? entry.tools.size : 0, connectedAt: entry.connectedAt ?? null };
  }

  return {
    invalidate,
    invalidateSecret(key) {
      for (const server of store.upstreams()) if (server.headers.some(header => header.secretKey === key)) invalidate(server.id);
    },
    describe,
    async statuses() { return await Promise.all(store.upstreams().map(describe)); },
    async reconnect(id) {
      invalidate(id);
      const server = store.upstream(id);
      if (!server) return undefined;
      store.audit('upstream.reconnected', 'admin', id);
      return await describe(server);
    },
    async listTools() {
      const results = await Promise.all(store.upstreams().map(async server => {
        const entry = await ensure(server);
        return entry.status === 'connected' && !entry.disposed ? [...entry.tools.values()].map(item => item.tool) : [];
      }));
      return results.flat();
    },
    async callTool(name, args, signal) {
      const separator = name.indexOf('__');
      if (separator < 0) return toolError('Tool not found. Refresh the tool catalog.');
      const server = store.upstream(name.slice(0, separator));
      if (!server || !server.enabled) return toolError('Upstream server is missing or disabled. Refresh the tool catalog.');
      const entry = await ensure(server);
      if (entry.status !== 'connected' || entry.disposed) return toolError('Upstream server is unavailable. Ask the vault administrator to check its connection.');
      const route = entry.tools.get(name);
      if (!route) return toolError('Upstream tool not found. Refresh the tool catalog.');
      try {
        store.audit('gateway.tool_called', 'agent', name);
        const result = await entry.client.callTool({ name: route.original, arguments: args ?? {} }, undefined, {
          timeout: server.timeoutMs, maxTotalTimeout: server.timeoutMs,
          signal: signal ? AbortSignal.any([signal, entry.abort.signal]) : entry.abort.signal,
        });
        if (entry.disposed || containsCredential(result, entry.credentials)) return toolError('Upstream result withheld because it may expose a configured credential or its connection was replaced.');
        // Forward valid content and structured output, not raw transport errors.
        return result;
      } catch {
        return toolError('Upstream tool request failed or timed out. It was not retried; check the upstream before repeating a potentially mutating action.');
      }
    },
    async close() {
      closed = true;
      const current = [...entries.values()];
      for (const id of [...entries.keys()]) invalidate(id);
      await Promise.all(current.map(entry => entry.client?.close().catch(() => {})));
    },
  };
}
