# Nod — Secret vault

A web app for key / secret value / description management, with authenticated credential APIs and a remote MCP gateway for AI agents. Requires **Node.js 24+**; uses the official MCP TypeScript SDK for MCP transport and validation.

## Run

```sh
npm ci
npm run setup
npm start
```

Open **http://localhost:3000** and sign in with the admin token printed by setup. Setup creates a private, Git-ignored `.env` with a random encryption key and separate admin and agent tokens. It refuses to overwrite an existing configuration. There are no demo secrets or default passwords.

Use the web console to add, edit, rotate, search, and delete secrets. Editing never loads an existing value into the browser; leave the value blank to preserve it. Activity records changes and successful agent access without secret values.

Use **Disable / Enable** in the secrets list or **Enable this secret** in the editor to temporarily revoke access without deleting the encrypted value. Disabled secrets remain visible to admins, but disappear from REST and MCP agent catalogs and cannot be retrieved, even by exact key. MCP servers referencing a disabled secret lose their connection and tools until it is re-enabled. Previously retrieved values cannot be revoked; rotate credentials at their provider if necessary. Existing secrets remain enabled when upgrading.

The console and API guide automatically follow your device's light or dark theme, including changes while the page is open.

```sh
npm test     # API, encryption, authentication, persistence, and security tests
npm run dev # server watch mode
```

## Docker

Build the image and generate credentials once (skip setup if `.env` already exists):

```sh
docker build -t nod-vault .
npm run setup
```

If Node.js is not installed on the host, generate the configuration using the image instead:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd),target=/setup" \
  --workdir /setup nod-vault node /app/scripts/setup.js
```

Run with runtime credentials and a persistent named volume:

```sh
docker run -d --name nod-vault --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  --env-file .env \
  -e HOST=0.0.0.0 \
  -e PORT=3000 \
  -e DATA_DIR=/app/data \
  -e APP_ORIGIN=http://localhost:3000 \
  --mount type=volume,source=nod-vault-data,target=/app/data \
  nod-vault
```

Open **http://localhost:3000**. The explicit environment overrides ensure the local `.env` defaults do not bind the container to loopback or change its database location. The image runs as the non-root `node` user and includes a health check. No credentials, database files, or local `.env` files are included in the build context or image.

The named volume survives container replacement. Keep the same `VAULT_ENCRYPTION_KEY` when reusing it. A new volume starts empty; it does not import an existing host database. If using a bind mount instead, its directory must be writable by the image's `node` user (UID/GID 1000).

For production, configure a TLS reverse proxy and replace the origin override with your HTTPS URL; set `SECURE_COOKIE=true`. Environment variables are visible to Docker administrators, so restrict Docker access and use your deployment platform's secret injection facilities where available.

### Automated container publishing

The GitHub Actions workflow in `.github/workflows/container.yml` runs on every push to `main` (and can also be started manually). It runs the Node.js tests first, then builds the Linux AMD64 container and publishes it to GitHub Container Registry using the built-in `GITHUB_TOKEN`.

Published tags:

- `ghcr.io/nphmuller/nod:latest`
- `ghcr.io/nphmuller/nod:sha-<full-commit-sha>`

```sh
docker pull ghcr.io/nphmuller/nod:latest
```

Use that image in place of `nod-vault` in the run instructions above. New GitHub packages may be private by default; change the package visibility to public if you want unauthenticated pulls, or authenticate Docker to GHCR with credentials authorized to read the package. Publishing requires GitHub Actions to be enabled and the repository's token policy to permit package writes. Action versions are pinned to commit SHAs.

## Agent API

Give a trusted agent the `AGENT_TOKEN` from `.env` through its tool runtime or secret manager. Do not put it in a prompt. Agents use `Authorization: Bearer <AGENT_TOKEN>`.

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `GET /api/v1` | Public | Discover available APIs |
| `GET /openapi.json` | Public | OpenAPI 3.1 tool definitions |
| `GET /llms.txt` | Public | Agent-readable instructions |
| `GET /.well-known/ai-plugin.json` | Public | OpenAPI discovery manifest |
| `GET /docs` | Public | Integration guide and examples |
| `GET /api/v1/keys` | Agent bearer token | List keys, descriptions, and timestamps; **no values** |
| `GET /api/v1/keys/{key}/value` | Agent bearer token | Retrieve one secret: `{ "key": "…", "value": "…" }` |

Point OpenAPI-capable agents to `http://localhost:3000/openapi.json`, or register the two operations as tools in your framework. Discoverability does not automatically register the app with every AI platform.

```sh
# AGENT_TOKEN should be injected by your runtime.
curl --fail http://localhost:3000/api/v1/keys \
  -H "Authorization: Bearer $AGENT_TOKEN"
```

Retrieve values **inside the tool runtime** and inject them directly into downstream API calls. Do not send returned values to chat transcripts or logs. The public `/docs` guide includes this pattern. Treat descriptions as untrusted data, not instructions.

## MCP server

Nod serves an authenticated, stateless **Streamable HTTP** MCP server at `/mcp`, using the same `AGENT_TOKEN` as the REST API:

- Local URL: `http://localhost:3000/mcp`
- Hosted URL: `https://nod.svc.nickmuller.dev:8443/mcp`
- Header on **every request**: `Authorization: Bearer <AGENT_TOKEN>`
- `list_keys`: returns keys, descriptions, and timestamps, never values.
- `get_secret`: accepts `{ "key": "EXACT_KEY" }` and returns the sensitive `{ "key", "value" }` result.

Nod's native credential tools remain read-only. Configured upstream tools are exposed alongside them and **may perform writes**. Tool calls use the existing metadata-only audit trail. REST and MCP share the agent rate limit. Admin tokens and session cookies do not authenticate MCP requests. The agent token grants access to all secrets and all enabled upstream tools in the vault.

For a generic MCP client supporting remote HTTP connections and custom headers:

```json
{
  "mcpServers": {
    "nod": {
      "url": "https://nod.svc.nickmuller.dev:8443/mcp",
      "headers": {
        "Authorization": "Bearer <AGENT_TOKEN>"
      }
    }
  }
}
```

Replace the placeholder using your client's secure credential or environment-variable mechanism. Config format and interpolation syntax vary by client; do not commit an actual token to a shared configuration file. This server uses a pre-provisioned bearer token, **not OAuth**; OAuth-only clients or clients without custom header support cannot connect directly.

An SDK client example (Node.js, using Nod's installed dependencies):

```js
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const client = new Client({ name: 'my-agent', version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(
  new URL(`${process.env.VAULT_URL}/mcp`),
  { requestInit: { headers: { Authorization: `Bearer ${process.env.AGENT_TOKEN}` } } }
));
const catalog = await client.callTool({ name: 'list_keys', arguments: {} });
// Expose only the catalog to the model. Retrieve values inside a trusted tool
// runtime and inject them into downstream requests without logging them.
await client.close();
```

**Security:** MCP `get_secret` returns the raw value to the client. Many agent clients put tool results into the model context or transcript. Enable this tool only for clients that can handle sensitive outputs safely; otherwise expose only the catalog and use a trusted runtime to fetch/inject values. Descriptions are untrusted metadata, not instructions.

The transport uses JSON-RPC POST requests with `Accept: application/json, text/event-stream`. It returns JSON responses, not persistent SSE streams. `GET` and `DELETE` return `405` after authentication because there are no subscriptions or server sessions. Supplied browser `Origin` headers must match `APP_ORIGIN`; originless tool clients are allowed. Legacy HTTP+SSE and stdio transports are not provided. `/api/v1` and `/llms.txt` advertise the MCP connection details without exposing credentials.

## MCP gateway

Configure trusted upstreams under **MCP servers** in the web console. An agent connects only to Nod's existing `/mcp` endpoint; no additional connection token or container environment variable is needed for each upstream.

1. Add the upstream credential as a secret in the vault.
2. Add a server with a stable ID such as `home_assistant`, its Streamable HTTP endpoint URL, and authentication mode.
3. For bearer auth, select the vault key. Nod sends `Authorization: Bearer <value>`. For custom auth, add header names, referenced vault keys, and optional prefixes. An empty prefix sends the raw credential value. Inline credential values are deliberately unsupported.
4. Check connection status, then refresh your agent's tool catalog or reconnect it to Nod.

Tools use names such as `home_assistant__HassTurnOn`, avoiding collisions with `list_keys`, `get_secret`, and tools from other servers. Original input/output JSON Schemas and annotations are preserved, including non-read-only tools. Nonstandard or oversized names receive a stable hash suffix. Both original credential REST endpoints remain unchanged.

Configurations persist in SQLite as endpoint/settings and **vault-key references**, not raw credentials. Credential values remain encrypted in the secret store and are resolved only inside Nod's server process. Editing a server, disabling/removing it, or rotating/deleting a referenced key invalidates the shared upstream connection. The next request reconnects with the current value, without restarting Nod or Docker. A connection failure omits that upstream's tools but does not hide native Nod tools or healthy upstreams. The UI keeps failed configurations so they can be corrected.

Upstream tool catalogs are cached per connection. Use **Reconnect** in Nod to rediscover an upstream catalog; upstream tool-list-change notifications also invalidate the connection. Since downstream MCP is stateless, Nod does not broadcast list-change notifications to agents: refresh `tools/list` or reconnect the agent after changes.

### Scope and security

- Supports **remote Streamable HTTP** only, with no auth, bearer auth, or custom vault-referenced credential headers. OAuth flows, local stdio, legacy SSE endpoints, prompts/resources, sampling/elicitation, and chained Nod gateways are not supported in this version.
- Only authenticated admins can configure endpoints. Private LAN endpoints are allowed for NAS services; configure only trusted destinations. HTTPS is the default requirement. Unencrypted HTTP requires explicit opt-in and sends credentials in plaintext on the network.
- Endpoint URLs cannot contain userinfo, query parameters, or fragments. Credential headers cannot override transport/session, host, cookie, origin, or proxy headers. HTTP redirects are not followed, so credentials cannot be forwarded to a redirected destination. Downstream authentication/cookies are not forwarded.
- Catalog discovery and tool calls have configurable 1–60 second timeouts (15 seconds by default). Upstream responses are bounded to 4 MiB, catalogs to 1,000 tools per upstream, and configurations to 32 servers. Failed connections have a five-second retry cooldown; manual reconnect bypasses it.
- Raw upstream errors are never sent to clients or logs. Results/catalogs containing literal configured credential values are withheld. **This is not a complete data-loss-prevention system:** a malicious upstream can encode/exfiltrate credentials, so it must be trusted. Upstream descriptions, schemas, and results are untrusted content, not agent instructions.
- Tool calls are audited by namespaced tool name without arguments, results, or credential values. Calls are **not automatically retried**, since writes may already have happened. Rotating credentials or disabling a server aborts local in-flight requests but cannot undo upstream actions.
- An agent bearer token can invoke **every enabled tool** and use `get_secret` to retrieve any vault key. Per-agent/key/tool permissions are not implemented. Keep distinct trust boundaries in separate vault instances and configure client-side approvals for mutating tools.

### Gateway administration API

These routes require the same admin session and mutation `Origin` checks as secret administration:

| Method and path | Purpose |
| --- | --- |
| `GET /api/admin/mcp-servers` | Server settings, connection status, and tool counts; no credential values |
| `POST /api/admin/mcp-servers` | Add a server and attempt connection |
| `PUT /api/admin/mcp-servers/{id}` | Replace settings and reconnect; IDs cannot change |
| `POST /api/admin/mcp-servers/{id}/reconnect` | Force reconnection and catalog rediscovery |
| `DELETE /api/admin/mcp-servers/{id}` | Remove a server, retaining its vault keys |

Example configuration (all fields shown):

```json
{
  "id": "home_assistant",
  "url": "https://your-home-assistant.example/api/mcp",
  "enabled": true,
  "allowInsecureHttp": false,
  "timeoutMs": 15000,
  "headers": [
    { "name": "Authorization", "secretKey": "HOMEASSISTANT_TOKEN", "prefix": "Bearer " }
  ]
}
```

Saving valid settings can succeed with `status: "failed"` if the upstream is unavailable or a key is missing. The configuration is retained; correct the key/URL and reconnect. There is no agent-facing server-management API.

## Administration API

The web console uses a separate admin session:

- `POST /api/auth/login` with `{ "token": "<ADMIN_TOKEN>" }` creates an eight-hour HttpOnly, SameSite=Strict cookie.
- `GET /api/auth/session` checks the session; `POST /api/auth/logout` invalidates it.
- `GET /api/admin/secrets` returns metadata only.
- `POST /api/admin/secrets` creates `{ "key", "description", "value" }`.
- `PUT /api/admin/secrets/{key}` updates `{ "description", "value"? }`. Omit `value` to preserve it; keys are immutable.
- `DELETE /api/admin/secrets/{key}` deletes a secret.
- `GET /api/admin/activity` returns the latest 50 events.

All admin endpoints require the session. Mutations and login also require an `Origin` header equal to `APP_ORIGIN`. Agent bearer tokens cannot access administration endpoints; admin tokens and cookies cannot access agent endpoints.

## Security and deployment

- AES-256-GCM encryption with a fresh random nonce per write; key names are authenticated as additional data. SQLite stores ciphertext, never plaintext values.
- Encryption key and tokens live outside the database. Local configuration and database permissions are restricted; `.env` and `data/` are Git-ignored.
- Secret responses and app responses are `Cache-Control: no-store`. No CORS, external analytics, CDN scripts, or third-party resources. CSP and clickjacking protections are enabled.
- API rate limiting: 120 agent requests/minute and 10 sign-in attempts/minute per connection IP. Behind a proxy, connection IP may be the proxy; forwarded headers are intentionally not trusted. Add proxy-level limits as needed.
- **An agent token grants access to every key in the vault.** Per-agent tokens, per-key scopes, expiry, and revocation management are not implemented. Use separate instances for distinct trust boundaries.
- This is a single-process, single-workspace app, not a multi-tenant production secrets service. Sessions and rate limits are in memory; restarts sign users out. Audit retention is not automatically pruned.
- Encryption at rest cannot protect against a compromised running server or theft of both the database and encryption key. Metadata and audit records are not encrypted.
- For production, terminate TLS at a trusted reverse proxy, set `APP_ORIGIN=https://your-vault.example`, `SECURE_COOKIE=true`, and restrict direct access to the backend. The default listener binds to loopback. Set `HOST=0.0.0.0` only in a controlled container/network.
- Set `APP_ORIGIN` to the exact browser origin (scheme, hostname, and port). `localhost` and `127.0.0.1` are different origins. If changing `PORT`, also change `APP_ORIGIN`.
- Back up `data/vault.sqlite` while the server is stopped, and store the encryption key separately and securely. Restore both to recover values. **Do not change the encryption key without re-encrypting the database.** Changing `AGENT_TOKEN` and restarting revokes the old agent token; changing `ADMIN_TOKEN` and restarting invalidates sessions.

## Layout

```text
server/index.js   HTTP server, auth, validation, routes, security headers
server/store.js   SQLite persistence, authenticated encryption, audit
server/openapi.js Machine-readable API schema
server/mcp.js     Native vault tools plus namespaced gateway tools over MCP
server/gateway.js Upstream connections, credential resolution, forwarding, and limits
public/          Responsive web console and integration guide
scripts/setup.js Safe first-time credential provisioning
test/            Node built-in test suite
```
