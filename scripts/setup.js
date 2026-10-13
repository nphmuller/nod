import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const adminToken = randomBytes(32).toString('base64url');
const agentToken = randomBytes(32).toString('base64url');
const contents = [
  `VAULT_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}`,
  `ADMIN_TOKEN=${adminToken}`,
  `AGENT_TOKEN=${agentToken}`,
  'HOST=127.0.0.1',
  'PORT=3000',
  'APP_ORIGIN=http://localhost:3000',
  'SECURE_COOKIE=false',
  'DATA_DIR=./data',
  '',
].join('\n');

try {
  writeFileSync('.env', contents, { flag: 'wx', mode: 0o600 });
  console.log('Vault configured. Keep .env private and back it up with your database.');
  console.log(`\nAdmin sign-in token: ${adminToken}`);
  console.log(`Agent API token:     ${agentToken}`);
  console.log('\nRun npm start, then open http://localhost:3000.');
} catch (error) {
  if (error.code === 'EEXIST') {
    console.error('.env already exists. Setup will not overwrite your encryption key or credentials.');
  } else {
    console.error(`Setup failed: ${error.message}`);
  }
  process.exitCode = 1;
}
