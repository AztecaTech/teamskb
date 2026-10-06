import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createMsalClient } from '../dist/token-cache.js';

test('local MSAL cache key must be a distinct 32-byte hex value', async () => {
  await assert.rejects(createMsalClient({
    clientId: 'client', tenantId: 'tenant', clientSecret: 'synthetic-secret',
    cacheKeyFile: '', cacheKeyHex: `${'a'.repeat(64)}zz`,
  }), /64 hexadecimal characters/);
});

test('an MSAL cache encrypted with an old key is discarded after key rotation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'iqkb-msal-cache-'));
  const cacheFile = join(directory, 'cache.bin');
  try {
    const oldKey = Buffer.alloc(32, 1);
    const newKey = Buffer.alloc(32, 2);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', oldKey, nonce);
    const ciphertext = Buffer.concat([cipher.update('{}', 'utf8'), cipher.final()]);
    await writeFile(cacheFile, Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]));

    const client = await createMsalClient({
      clientId: 'client', tenantId: 'tenant', clientSecret: 'synthetic-secret',
      cacheKeyFile: '', cacheKeyHex: newKey.toString('hex'), cacheFile,
    });
    assert.deepEqual(await client.getTokenCache().getAllAccounts(), []);
    await assert.rejects(readFile(cacheFile), { code: 'ENOENT' });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
