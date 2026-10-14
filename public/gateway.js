// Classic deferred script: share the console's authenticated API and navigation.
let upstreams = [];
let editingUpstream = null;
let removingUpstream = null;
let upstreamLoadVersion = 0;

const gatewayNav = document.createElement('button');
gatewayNav.className = 'nav-item';
gatewayNav.dataset.view = 'upstreams';
gatewayNav.innerHTML = '<svg class="icon"><use href="#i-code"/></svg> MCP servers <span id="upstream-count" class="nav-count" hidden>0</span>';
$('.sidebar nav').insertBefore(gatewayNav, $('.nav-item[data-view="activity"]'));
gatewayNav.addEventListener('click', () => switchView('upstreams').catch(error => notify(error.message)));

const gatewayView = document.createElement('section');
gatewayView.id = 'view-upstreams';
gatewayView.className = 'view';
gatewayView.hidden = true;
gatewayView.innerHTML = `
  <div class="page-heading"><div><span class="eyebrow">ONE CONNECTION. ALL YOUR TOOLS.</span><h1>MCP servers<span class="heading-dot">.</span></h1><p>Connect trusted remote servers. Keep their credentials in your vault.</p></div><button id="add-upstream" class="button primary">+ Add server</button></div>
  <div class="api-intro"><span class="banner-icon"><svg class="icon"><use href="#i-shield"/></svg></span><div><h3>Your agent connects only to Nod.</h3><p>Upstream tools appear as <code>server_id__tool_name</code>. Nod injects credentials inside the gateway. Your existing <code>list_keys</code>, <code>get_secret</code>, and REST APIs remain available. Remote Streamable HTTP only; no OAuth or stdio.</p></div></div>
  <div class="catalog-toolbar gateway-toolbar"><strong>Configured servers</strong><button id="refresh-upstreams" class="button secondary">Refresh connections</button></div>
  <p id="upstream-error" class="form-error" role="alert"></p><div id="upstream-list" class="gateway-list" aria-live="polite"></div>
  <div id="upstream-empty" class="catalog empty-state" hidden><div class="empty-icon"><svg class="icon"><use href="#i-code"/></svg></div><h3>Bring your tools together.</h3><p>Add an upstream server and reference its credential by vault key.<br>No credentials are sent back to this configuration form.</p><button id="empty-upstream-add" class="button secondary">+ Add your first server</button></div>
  <p class="field-note gateway-warning">Only add endpoints you trust. Upstream tools can perform writes, and their descriptions and results are untrusted. Every holder of Nod's agent token can invoke all enabled upstream tools. After changing servers, refresh your agent's tool catalog or reconnect it to Nod.</p>`;
$('#app main').append(gatewayView);

const upstreamDialog = document.createElement('dialog');
upstreamDialog.id = 'upstream-dialog';
upstreamDialog.innerHTML = `
  <form id="upstream-form"><div class="dialog-heading"><div><span class="eyebrow">A TRUSTED PATH TO YOUR TOOLS</span><h2 id="upstream-dialog-title">Add MCP server</h2></div><button id="close-upstream" type="button" class="icon-button" aria-label="Close server dialog">×</button></div>
  <label for="upstream-id">Server ID *</label><input id="upstream-id" pattern="[a-z]([a-z0-9_]{0,30}[a-z0-9])?" maxlength="32" placeholder="e.g. home_assistant" autocomplete="off" required><p class="field-note">Lowercase letters, numbers, and single underscores; no trailing underscore. IDs are immutable and become the tool namespace.</p>
  <label for="upstream-url">Streamable HTTP endpoint *</label><input id="upstream-url" type="url" placeholder="https://your-service.example/mcp" autocomplete="off" required><p class="field-note">No credentials or query parameters in the URL. Nod does not follow redirects.</p>
  <div class="gateway-options"><label class="gateway-check"><input id="upstream-enabled" type="checkbox" checked> Enable this server</label><label class="gateway-check"><input id="upstream-http" type="checkbox"> Allow unencrypted HTTP (trusted network only)</label></div>
  <label for="upstream-timeout">Connection / tool timeout (seconds)</label><input id="upstream-timeout" type="number" min="1" max="60" step="1" value="15" required>
  <label for="upstream-auth">Authentication</label><select id="upstream-auth" class="gateway-select"><option value="none">None</option><option value="bearer">Bearer token from vault</option><option value="custom">Custom credential headers</option></select>
  <div id="credential-headers"></div><button id="add-credential-header" type="button" class="button secondary" hidden>+ Add header</button>
  <p class="field-note">Create credentials in Secrets first. Each header references a key, never a copied token. Rotating a referenced value replaces its upstream connection on the next request. For custom headers, an empty prefix sends the raw value.</p>
  <p id="upstream-form-error" class="form-error" role="alert"></p><div class="dialog-footer"><span><svg class="icon"><use href="#i-lock"/></svg> Vault-held credentials</span><button id="cancel-upstream" type="button" class="button secondary">Cancel</button><button id="save-upstream" type="submit" class="button primary">Save server</button></div></form>`;
document.body.append(upstreamDialog);

const upstreamDeleteDialog = document.createElement('dialog');
upstreamDeleteDialog.className = 'delete-dialog';
upstreamDeleteDialog.id = 'upstream-delete-dialog';
upstreamDeleteDialog.innerHTML = '<form id="upstream-delete-form"><span class="eyebrow">REMOVE A CONNECTION</span><h2>Remove this MCP server?</h2><p>Tools from <strong id="upstream-delete-id"></strong> will no longer be available through Nod. Its secret keys stay in your vault.</p><p id="upstream-delete-error" class="form-error" role="alert"></p><div class="delete-actions"><button id="cancel-upstream-delete" type="button" class="button secondary">Keep server</button><button type="submit" class="button danger">Remove server</button></div></form>';
document.body.append(upstreamDeleteDialog);

function clearGatewayUI() {
  upstreamLoadVersion++;
  upstreams = [];
  $('#upstream-list').replaceChildren();
  $('#upstream-form').reset();
  $('#credential-headers').replaceChildren();
  $('#upstream-count').textContent = '0';
  $('#upstream-count').hidden = true;
}

async function loadUpstreams() {
  const version = ++upstreamLoadVersion;
  $('#upstream-error').textContent = '';
  try {
    const data = await api('/api/admin/mcp-servers');
    if (version !== upstreamLoadVersion || $('#app').hidden) return;
    upstreams = data.servers;
    renderUpstreams();
  } catch (error) {
    if (version === upstreamLoadVersion) $('#upstream-error').textContent = error.message;
    throw error;
  }
}

function upstreamConfig(server) {
  return { id: server.id, url: server.url, enabled: server.enabled, timeoutMs: server.timeoutMs, allowInsecureHttp: server.allowInsecureHttp, headers: server.headers };
}

async function upstreamAction(button, action) {
  button.disabled = true;
  try { await action(); await loadUpstreams(); }
  catch (error) { notify(error.message); }
  finally { button.disabled = false; }
}

function renderUpstreams() {
  $('#upstream-count').textContent = upstreams.length;
  $('#upstream-count').hidden = false;
  $('#upstream-empty').hidden = upstreams.length !== 0;
  const cards = upstreams.map(server => {
    const card = document.createElement('article');
    card.className = 'api-card gateway-card';
    card.innerHTML = '<div class="gateway-card-heading"><h2></h2><span class="gateway-status"></span></div><p class="gateway-url"></p><p class="gateway-credentials"></p><p class="gateway-summary"></p><p class="gateway-connection-error form-error"></p><div class="gateway-actions"><button class="button secondary gateway-edit">Edit</button><button class="button secondary gateway-reconnect">Reconnect</button><button class="button secondary gateway-toggle"></button><button class="button secondary gateway-remove">Remove</button></div>';
    card.querySelector('h2').textContent = server.id;
    const status = card.querySelector('.gateway-status');
    status.textContent = server.status;
    status.classList.add(`gateway-status-${server.status}`);
    card.querySelector('.gateway-url').textContent = server.url;
    card.querySelector('.gateway-credentials').textContent = server.headers.length ? server.headers.map(header => `${header.name} ← ${header.secretKey}`).join(' · ') : 'No authentication headers';
    card.querySelector('.gateway-summary').textContent = `${server.toolCount} tool${server.toolCount === 1 ? '' : 's'} · ${server.timeoutMs / 1000}s timeout · namespace ${server.id}__`;
    card.querySelector('.gateway-connection-error').textContent = server.error ?? '';
    card.querySelector('.gateway-edit').addEventListener('click', () => openUpstream(server).catch(error => notify(error.message)));
    const reconnect = card.querySelector('.gateway-reconnect');
    reconnect.disabled = !server.enabled;
    reconnect.addEventListener('click', () => upstreamAction(reconnect, async () => {
      await api(`/api/admin/mcp-servers/${server.id}/reconnect`, { method: 'POST' });
      notify('Connection refreshed. Refresh your agent’s tool catalog to see changes.');
    }));
    const toggle = card.querySelector('.gateway-toggle');
    toggle.textContent = server.enabled ? 'Disable' : 'Enable';
    toggle.addEventListener('click', () => upstreamAction(toggle, async () => {
      await api(`/api/admin/mcp-servers/${server.id}`, { method: 'PUT', body: JSON.stringify({ ...upstreamConfig(server), enabled: !server.enabled }) });
      notify(server.enabled ? 'Server disabled.' : 'Server enabled.');
    }));
    card.querySelector('.gateway-remove').addEventListener('click', () => {
      removingUpstream = server.id;
      $('#upstream-delete-id').textContent = server.id;
      $('#upstream-delete-error').textContent = '';
      upstreamDeleteDialog.showModal();
      $('#cancel-upstream-delete').focus();
    });
    return card;
  });
  $('#upstream-list').replaceChildren(...cards);
}

function addCredentialHeader(header = {}, bearer = false) {
  const row = document.createElement('div');
  row.className = 'credential-header';
  row.innerHTML = '<label>Header name<input class="header-name" autocomplete="off" required></label><label>Vault key<select class="header-key gateway-select" required><option value="">Choose a secret key…</option></select></label><label>Prefix<input class="header-prefix" placeholder="Optional, e.g. Bearer "></label><button type="button" class="icon-button remove-header" aria-label="Remove credential header">×</button>';
  row.querySelector('.header-name').value = bearer ? 'Authorization' : header.name ?? '';
  row.querySelector('.header-name').readOnly = bearer;
  row.querySelector('.header-prefix').value = bearer ? 'Bearer ' : header.prefix ?? '';
  row.querySelector('.header-prefix').readOnly = bearer;
  const select = row.querySelector('.header-key');
  const available = [...keys];
  if (header.secretKey && !available.some(key => key.key === header.secretKey)) available.push({ key: header.secretKey, missing: true });
  for (const key of available) {
    const option = document.createElement('option');
    option.value = key.key;
    option.textContent = key.key + (key.missing ? ' (missing)' : '');
    select.append(option);
  }
  select.value = header.secretKey ?? '';
  const remove = row.querySelector('.remove-header');
  remove.hidden = bearer;
  remove.addEventListener('click', () => row.remove());
  $('#credential-headers').append(row);
}

function changeUpstreamAuth(headers = []) {
  const mode = $('#upstream-auth').value;
  $('#credential-headers').replaceChildren();
  $('#add-credential-header').hidden = mode !== 'custom';
  if (mode === 'bearer') addCredentialHeader(headers[0] ?? {}, true);
  if (mode === 'custom') for (const header of headers.length ? headers : [{}]) addCredentialHeader(header);
}

async function openUpstream(server = null) {
  await loadKeys();
  if ($('#app').hidden) return;
  editingUpstream = server?.id ?? null;
  $('#upstream-form').reset();
  $('#upstream-form-error').textContent = '';
  $('#upstream-dialog-title').textContent = server ? 'Edit MCP server' : 'Add MCP server';
  $('#upstream-id').value = server?.id ?? '';
  $('#upstream-id').readOnly = Boolean(server);
  $('#upstream-url').value = server?.url ?? '';
  $('#upstream-enabled').checked = server?.enabled ?? true;
  $('#upstream-http').checked = server?.allowInsecureHttp ?? false;
  $('#upstream-timeout').value = (server?.timeoutMs ?? 15000) / 1000;
  const headers = server?.headers ?? [];
  $('#upstream-auth').value = headers.length === 0 ? 'none' : headers.length === 1 && headers[0].name.toLowerCase() === 'authorization' && headers[0].prefix === 'Bearer ' ? 'bearer' : 'custom';
  changeUpstreamAuth(headers);
  upstreamDialog.showModal();
  $(server ? '#upstream-url' : '#upstream-id').focus();
}

$('#add-upstream').addEventListener('click', () => openUpstream().catch(error => notify(error.message)));
$('#empty-upstream-add').addEventListener('click', () => openUpstream().catch(error => notify(error.message)));
$('#refresh-upstreams').addEventListener('click', event => upstreamAction(event.currentTarget, async () => {}));
$('#upstream-auth').addEventListener('change', () => changeUpstreamAuth());
$('#add-credential-header').addEventListener('click', () => {
  if (document.querySelectorAll('.credential-header').length >= 16) return notify('A server supports up to 16 credential headers.');
  addCredentialHeader();
});
$('#close-upstream').addEventListener('click', () => upstreamDialog.close());
$('#cancel-upstream').addEventListener('click', () => upstreamDialog.close());
$('#cancel-upstream-delete').addEventListener('click', () => upstreamDeleteDialog.close());
$('#upstream-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#save-upstream');
  button.disabled = true;
  $('#upstream-form-error').textContent = '';
  const config = {
    id: $('#upstream-id').value, url: $('#upstream-url').value,
    enabled: $('#upstream-enabled').checked, allowInsecureHttp: $('#upstream-http').checked,
    timeoutMs: Number($('#upstream-timeout').value) * 1000,
    headers: [...document.querySelectorAll('.credential-header')].map(row => ({ name: row.querySelector('.header-name').value.trim(), secretKey: row.querySelector('.header-key').value, prefix: row.querySelector('.header-prefix').value })),
  };
  try {
    if ($('#upstream-auth').value !== 'none' && config.headers.length === 0) throw new Error('Add a credential header, or choose no authentication.');
    const saved = await api(editingUpstream ? `/api/admin/mcp-servers/${editingUpstream}` : '/api/admin/mcp-servers', { method: editingUpstream ? 'PUT' : 'POST', body: JSON.stringify(config) });
    upstreamDialog.close();
    notify(saved.status === 'failed' ? 'Server saved, but connection failed. Check its configuration.' : 'Server saved. Refresh your agent’s tool catalog.');
    await loadUpstreams();
  } catch (error) { $('#upstream-form-error').textContent = error.message; if (!upstreamDialog.open) notify(error.message); }
  finally { button.disabled = false; }
});
$('#upstream-delete-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    await api(`/api/admin/mcp-servers/${removingUpstream}`, { method: 'DELETE' });
    upstreamDeleteDialog.close();
    notify('Server removed. Vault credentials were kept.');
    await loadUpstreams();
  } catch (error) { $('#upstream-delete-error').textContent = error.message; }
  finally { button.disabled = false; }
});
