import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

export function createStore(directory, encryptionKey) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const file = join(directory, 'vault.sqlite');
  const db = new DatabaseSync(file);
  chmodSync(file, 0o600);
  db.exec(`
    PRAGMA journal_mode = DELETE;
    PRAGMA secure_delete = ON;
    CREATE TABLE IF NOT EXISTS secrets (
      key TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      encrypted_value TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      key TEXT,
      timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mcp_servers (
      id TEXT PRIMARY KEY,
      config TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  // Existing vaults predate per-secret availability. Keep those secrets enabled.
  if (!db.prepare('PRAGMA table_info(secrets)').all().some(column => column.name === 'enabled')) {
    db.exec('ALTER TABLE secrets ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))');
  }

  function encrypt(key, value) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
    cipher.setAAD(Buffer.from(key));
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), ciphertext].map(part => part.toString('base64')).join('.');
  }

  function decrypt(key, encrypted) {
    const [iv, tag, ciphertext] = encrypted.split('.').map(part => Buffer.from(part, 'base64'));
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAAD(Buffer.from(key));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }

  const metadata = row => row && ({ key: row.key, description: row.description, enabled: Boolean(row.enabled), createdAt: row.created_at, updatedAt: row.updated_at });
  const find = db.prepare('SELECT * FROM secrets WHERE key = ?');
  const recordAudit = db.prepare('INSERT INTO audit (action, actor, key, timestamp) VALUES (?, ?, ?, ?)');
  function audit(action, actor, key = null) {
    recordAudit.run(action, actor, key, new Date().toISOString());
  }
  function transaction(operation) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = operation();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  return {
    list({ includeDisabled = false } = {}) {
      const rows = db.prepare(`SELECT key, description, enabled, created_at, updated_at FROM secrets ${includeDisabled ? '' : 'WHERE enabled = 1'} ORDER BY key COLLATE NOCASE`).all().map(metadata);
      // Keep the agent catalog's existing schema; availability is admin metadata.
      return includeDisabled ? rows : rows.map(({ enabled, ...item }) => item);
    },
    get(key) { return metadata(find.get(key)); },
    value(key) {
      const row = find.get(key);
      return row?.enabled ? decrypt(key, row.encrypted_value) : undefined;
    },
    save(key, description, value, actor = 'admin', enabled) {
      return transaction(() => {
        const existing = find.get(key);
        const now = new Date().toISOString();
        const encrypted = value === undefined ? existing?.encrypted_value : encrypt(key, value);
        if (!encrypted) throw new Error('A new secret requires a value.');
        const available = enabled === undefined ? existing?.enabled ?? 1 : Number(enabled);
        db.prepare(`INSERT INTO secrets (key, description, encrypted_value, created_at, updated_at, enabled) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(key) DO UPDATE SET description = excluded.description,
          encrypted_value = excluded.encrypted_value, updated_at = excluded.updated_at, enabled = excluded.enabled`)
          .run(key, description, encrypted, existing?.created_at ?? now, now, available);
        audit(existing ? 'secret.updated' : 'secret.created', actor, key);
        if (existing && existing.enabled !== available) audit(available ? 'secret.enabled' : 'secret.disabled', actor, key);
        return metadata(find.get(key));
      });
    },
    delete(key) {
      return transaction(() => {
        const deleted = db.prepare('DELETE FROM secrets WHERE key = ?').run(key).changes > 0;
        if (deleted) audit('secret.deleted', 'admin', key);
        return deleted;
      });
    },
    audit,
    upstreams() {
      return db.prepare('SELECT * FROM mcp_servers ORDER BY id').all().map(row => ({ ...JSON.parse(row.config), createdAt: row.created_at, updatedAt: row.updated_at }));
    },
    upstream(id) {
      const row = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(id);
      return row && { ...JSON.parse(row.config), createdAt: row.created_at, updatedAt: row.updated_at };
    },
    saveUpstream(config) {
      return transaction(() => {
        const existing = db.prepare('SELECT created_at FROM mcp_servers WHERE id = ?').get(config.id);
        const now = new Date().toISOString();
        // Only secret-key references are stored here, never credential values.
        db.prepare(`INSERT INTO mcp_servers VALUES (?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`)
          .run(config.id, JSON.stringify(config), existing?.created_at ?? now, now);
        audit(existing ? 'upstream.updated' : 'upstream.created', 'admin', config.id);
        return { ...config, createdAt: existing?.created_at ?? now, updatedAt: now };
      });
    },
    deleteUpstream(id) {
      return transaction(() => {
        const deleted = db.prepare('DELETE FROM mcp_servers WHERE id = ?').run(id).changes > 0;
        if (deleted) audit('upstream.deleted', 'admin', id);
        return deleted;
      });
    },
    activity() {
      return db.prepare('SELECT action, actor, key, timestamp FROM audit ORDER BY id DESC LIMIT 50').all();
    },
    close() { db.close(); },
  };
}
