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
  `);

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

  const metadata = row => row && ({ key: row.key, description: row.description, createdAt: row.created_at, updatedAt: row.updated_at });
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
    list() {
      return db.prepare('SELECT key, description, created_at, updated_at FROM secrets ORDER BY key COLLATE NOCASE').all().map(metadata);
    },
    get(key) { return metadata(find.get(key)); },
    value(key) {
      const row = find.get(key);
      return row ? decrypt(key, row.encrypted_value) : undefined;
    },
    save(key, description, value, actor = 'admin') {
      return transaction(() => {
        const existing = find.get(key);
        const now = new Date().toISOString();
        const encrypted = value === undefined ? existing?.encrypted_value : encrypt(key, value);
        if (!encrypted) throw new Error('A new secret requires a value.');
        db.prepare(`INSERT INTO secrets VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(key) DO UPDATE SET description = excluded.description,
          encrypted_value = excluded.encrypted_value, updated_at = excluded.updated_at`)
          .run(key, description, encrypted, existing?.created_at ?? now, now);
        audit(existing ? 'secret.updated' : 'secret.created', actor, key);
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
    activity() {
      return db.prepare('SELECT action, actor, key, timestamp FROM audit ORDER BY id DESC LIMIT 50').all();
    },
    close() { db.close(); },
  };
}
