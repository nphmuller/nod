const $ = selector => document.querySelector(selector);
let keys = [];
let editKey = null;
let deleteKey = null;
let currentView = 'secrets';
let toastTimer;

const secretAvailability = document.createElement('div');
secretAvailability.className = 'gateway-options';
secretAvailability.innerHTML = '<label class="gateway-check"><input id="secret-enabled" type="checkbox" checked> Enable this secret</label><p class="field-note">Disabled secrets stay encrypted, but are hidden from agents and cannot be used by MCP servers.</p>';
$('#secret-error').before(secretAvailability);

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/auth/login') lock();
    throw new Error(data.error ?? 'Something went wrong. Please try again.');
  }
  return data;
}

function notify(message) {
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 4000);
}

function lock() {
  $('#app').hidden = true;
  $('#login-screen').hidden = false;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  $('#secret-form').reset();
  keys = [];
  $('#secret-rows').replaceChildren();
  $('#activity-list').replaceChildren();
  if (typeof clearGatewayUI === 'function') clearGatewayUI();
  $('#admin-token').value = '';
}

async function unlock() {
  await loadKeys();
  $('#login-screen').hidden = true;
  $('#app').hidden = false;
  $('#admin-token').value = '';
  await switchView('secrets');
}

function dateLabel(value) {
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value));
}

async function loadKeys() {
  const data = await api('/api/admin/secrets');
  keys = data.keys;
  renderKeys();
}

function renderKeys() {
  const query = $('#search').value.trim().toLowerCase();
  const filtered = keys.filter(item => `${item.key} ${item.description}`.toLowerCase().includes(query));
  $('#nav-count').textContent = keys.length;
  $('#total-secrets').textContent = keys.length;
  $('#catalog-count').textContent = keys.length;
  $('#showing-count').textContent = `${filtered.length}${query ? ` of ${keys.length}` : ''} secret${filtered.length === 1 ? '' : 's'}`;
  $('#empty-state').hidden = keys.length !== 0;
  $('#search-empty').hidden = keys.length === 0 || filtered.length !== 0;
  const rows = filtered.map(item => {
    const row = document.createElement('tr');
    row.innerHTML = '<td><div class="key-cell"><span class="key-tile"><svg class="icon"><use href="#i-key"/></svg></span><div class="key-info"><button class="key-name"></button><p class="key-description"></p></div></div></td><td><span class="masked-value">••••••••••••</span><span class="encrypted-label"><svg class="icon"><use href="#i-lock"/></svg> Encrypted</span></td><td class="date-cell"></td><td class="row-actions"><button class="edit-action" title="Edit secret">Edit</button><button class="delete-action" title="Delete secret" aria-label="Delete secret">×</button></td>';
    row.querySelector('.key-name').textContent = item.key;
    row.querySelector('.key-name').addEventListener('click', () => openSecret(item));
    row.querySelector('.key-description').textContent = item.description;
    if (!item.enabled) {
      const status = document.createElement('span');
      status.className = 'gateway-status';
      status.textContent = 'Disabled';
      row.querySelector('.key-info').append(status);
    }
    const toggle = document.createElement('button');
    toggle.className = 'edit-action';
    toggle.textContent = item.enabled ? 'Disable' : 'Enable';
    toggle.setAttribute('aria-label', `${toggle.textContent} ${item.key}`);
    toggle.addEventListener('click', async () => {
      toggle.disabled = true;
      try {
        await api(`/api/admin/secrets/${encodeURIComponent(item.key)}`, { method: 'PUT', body: JSON.stringify({ enabled: !item.enabled }) });
        notify(item.enabled ? 'Secret disabled.' : 'Secret enabled.');
        await loadKeys();
      } catch (error) { notify(error.message); }
      finally { toggle.disabled = false; }
    });
    row.querySelector('.delete-action').before(toggle);
    row.querySelector('.date-cell').textContent = dateLabel(item.updatedAt);
    row.querySelector('.date-cell').title = new Date(item.updatedAt).toLocaleString();
    row.querySelector('.edit-action').addEventListener('click', () => openSecret(item));
    row.querySelector('.delete-action').addEventListener('click', () => {
      deleteKey = item.key;
      $('#delete-key').textContent = item.key;
      $('#delete-error').textContent = '';
      $('#delete-dialog').showModal();
      $('#cancel-delete').focus();
    });
    return row;
  });
  $('#secret-rows').replaceChildren(...rows);
}

async function switchView(view) {
  currentView = view;
  document.querySelectorAll('.view').forEach(section => { section.hidden = section.id !== `view-${view}`; });
  document.querySelectorAll('.nav-item').forEach(button => {
    button.classList.toggle('active', button.dataset.view === view);
    if (button.dataset.view === view) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  $('#breadcrumb-current').textContent = { secrets: 'Secrets', activity: 'Activity', connect: 'Agent API', upstreams: 'MCP servers' }[view];
  if (view === 'activity') await loadActivity();
  if (view === 'upstreams') await loadUpstreams();
}

async function loadActivity() {
  const data = await api('/api/admin/activity');
  const labels = {
    'secret.created': 'Secret created', 'secret.updated': 'Secret updated', 'secret.deleted': 'Secret deleted',
    'secret.enabled': 'Secret enabled', 'secret.disabled': 'Secret disabled',
    'secret.retrieved': 'Secret retrieved', 'catalog.listed': 'Key catalog requested', 'session.started': 'Signed in to the vault',
    'upstream.created': 'MCP server added', 'upstream.updated': 'MCP server updated', 'upstream.deleted': 'MCP server removed',
    'upstream.reconnected': 'MCP server reconnected', 'gateway.tool_called': 'Upstream tool called',
  };
  const rows = data.activity.map(item => {
    const row = document.createElement('div');
    row.className = 'activity-row';
    row.innerHTML = '<span class="activity-dot"></span><div><strong></strong><p></p></div><span class="actor-badge"></span><time></time>';
    row.querySelector('strong').textContent = labels[item.action] ?? item.action;
    row.querySelector('p').textContent = item.key ?? 'Workspace';
    row.querySelector('.actor-badge').textContent = item.actor;
    row.querySelector('time').textContent = new Date(item.timestamp).toLocaleString();
    row.querySelector('time').dateTime = item.timestamp;
    return row;
  });
  if (!rows.length) {
    const empty = document.createElement('p');
    empty.className = 'search-empty';
    empty.textContent = 'No activity yet. Your vault’s story starts here.';
    rows.push(empty);
  }
  $('#activity-list').replaceChildren(...rows);
}

function openSecret(item = null) {
  editKey = item?.key ?? null;
  $('#secret-form').reset();
  $('#secret-error').textContent = '';
  $('#dialog-title').textContent = item ? 'Edit secret' : 'Add a secret';
  $('#secret-key').value = item?.key ?? '';
  $('#secret-key').readOnly = Boolean(item);
  $('#secret-description').value = item?.description ?? '';
  $('#secret-enabled').checked = item?.enabled ?? true;
  $('#secret-value').type = 'password';
  $('#secret-value').required = !item;
  $('#secret-value').placeholder = item ? 'Leave blank to keep the current value' : 'Paste your secret value';
  $('#value-required').textContent = item ? '(optional)' : '*';
  $('#value-note').textContent = item ? 'Existing values are never sent to this form. Enter a new value to replace it.' : 'Encrypted before it is stored. Never included in the key catalog.';
  $('#toggle-value').textContent = 'Show';
  $('#secret-dialog').showModal();
  $(item ? '#secret-description' : '#secret-key').focus();
}

$('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  $('#login-error').textContent = '';
  try {
    await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: $('#admin-token').value.trim() }) });
    await unlock();
  } catch (error) { $('#login-error').textContent = error.message; }
  finally { button.disabled = false; }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); lock(); }
  catch (error) { notify(error.message); }
});

document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view).catch(error => notify(error.message))));
$('#refresh-activity').addEventListener('click', () => loadActivity().catch(error => notify(error.message)));
$('#search').addEventListener('input', renderKeys);
document.addEventListener('keydown', event => {
  if (event.key === '/' && currentView === 'secrets' && !$('#app').hidden && !document.querySelector('dialog[open]') && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
    event.preventDefault();
    $('#search').focus();
  }
});
$('#add-secret').addEventListener('click', () => openSecret());
$('#empty-add').addEventListener('click', () => openSecret());
$('#close-dialog').addEventListener('click', () => $('#secret-dialog').close());
$('#cancel-dialog').addEventListener('click', () => $('#secret-dialog').close());
$('#secret-dialog').addEventListener('close', () => { $('#secret-form').reset(); $('#secret-value').type = 'password'; });
$('#toggle-value').addEventListener('click', () => {
  const show = $('#secret-value').type === 'password';
  $('#secret-value').type = show ? 'text' : 'password';
  $('#toggle-value').textContent = show ? 'Hide' : 'Show';
});
$('#secret-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#save-secret');
  button.disabled = true;
  $('#secret-error').textContent = '';
  const data = { key: $('#secret-key').value, description: $('#secret-description').value, enabled: $('#secret-enabled').checked };
  if (!editKey || $('#secret-value').value !== '') data.value = $('#secret-value').value;
  try {
    await api(editKey ? `/api/admin/secrets/${encodeURIComponent(editKey)}` : '/api/admin/secrets', { method: editKey ? 'PUT' : 'POST', body: JSON.stringify(data) });
    $('#secret-dialog').close();
    notify(editKey ? 'Secret updated. Safely stored.' : 'Secret added. Safely stored.');
    await loadKeys();
  } catch (error) { $('#secret-error').textContent = error.message; if (!$('#secret-dialog').open) notify(error.message); }
  finally { button.disabled = false; }
});
$('#cancel-delete').addEventListener('click', () => $('#delete-dialog').close());
$('#delete-form').addEventListener('submit', async event => {
  event.preventDefault();
  event.submitter.disabled = true;
  try {
    await api(`/api/admin/secrets/${encodeURIComponent(deleteKey)}`, { method: 'DELETE' });
    $('#delete-dialog').close();
    notify('Secret deleted.');
    await loadKeys();
  } catch (error) { $('#delete-error').textContent = error.message; if (!$('#delete-dialog').open) notify(error.message); }
  finally { event.submitter.disabled = false; }
});

const base = location.origin;
const mcpCard = document.createElement('article');
mcpCard.className = 'api-card mcp-card';
mcpCard.innerHTML = '<span class="step-label">CONNECT WITH MCP</span><h2>Your vault and tools. One connection.</h2><p>Use a Streamable HTTP client with your existing agent token. <code>list_keys</code> discovers credentials without values; <code>get_secret</code> retrieves one exact key. Configure remote servers in MCP servers to add namespaced upstream tools. Credential tools are read-only; upstream tools may perform writes.</p><div class="copy-field"><code class="mcp-url"></code><button class="icon-button copy-mcp" aria-label="Copy MCP URL"><svg class="icon"><use href="#i-copy"/></svg></button></div><pre><code class="mcp-config"></code></pre><p>Send <code>Authorization: Bearer &lt;AGENT_TOKEN&gt;</code> on every request. This uses a pre-provisioned token, not OAuth. The configuration format depends on your client.</p><p><strong>Keep secret outputs out of conversations.</strong> Many MCP clients send tool results to the model or save them in transcripts. Enable <code>get_secret</code> only in a client that handles sensitive results safely.</p><a class="text-link" href="/docs">Read the MCP integration guide ↗</a>';
mcpCard.querySelector('.mcp-url').textContent = `${base}/mcp`;
mcpCard.querySelector('.mcp-config').textContent = JSON.stringify({ mcpServers: { nod: { url: `${base}/mcp`, headers: { Authorization: 'Bearer <AGENT_TOKEN>' } } } }, null, 2);
mcpCard.querySelector('.copy-mcp').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(`${base}/mcp`); notify('MCP URL copied.'); }
  catch { notify('Copy is unavailable. Select and copy the URL above.'); }
});
$('#view-connect .api-cards').append(mcpCard);
$('#schema-url').textContent = `${base}/openapi.json`;
$('#list-command').textContent = `curl "${base}/api/v1/keys" \\\n  -H "Authorization: Bearer $AGENT_TOKEN"`;
$('#value-command').textContent = `curl "${base}/api/v1/keys/STRIPE_API_KEY/value" \\\n  -H "Authorization: Bearer $AGENT_TOKEN"`;
$('#copy-schema').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(`${base}/openapi.json`); notify('OpenAPI URL copied.'); }
  catch { notify('Copy is unavailable. Select and copy the URL above.'); }
});

api('/api/auth/session').then(unlock).catch(error => {
  if (error.message !== 'Sign in to the vault to continue.') $('#login-error').textContent = error.message;
});
