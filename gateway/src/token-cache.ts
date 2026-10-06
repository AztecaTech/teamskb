import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { ConfidentialClientApplication, type ICachePlugin, type TokenCacheContext } from '@azure/msal-node';

type Options = { clientId: string; tenantId: string; clientSecret: string; cacheKeyFile: string; cacheKeyHex?: string; cacheFile?: string };

export async function createMsalClient(options: Options): Promise<ConfidentialClientApplication> {
  if (options.cacheKeyHex && !/^[0-9a-fA-F]{64}$/.test(options.cacheKeyHex)) {
    throw new Error('MSAL cache key must be exactly 64 hexadecimal characters');
  }
  const key = options.cacheKeyHex ? Buffer.from(options.cacheKeyHex, 'hex') : await readFile(options.cacheKeyFile);
  if (key.length !== 32) throw new Error('MSAL cache key must be exactly 32 bytes');
  const path = options.cacheFile ?? '/var/lib/iqkb-msal/cache.bin';
  let unlock = () => {};
  let tail = Promise.resolve();

  const cachePlugin: ICachePlugin = {
    beforeCacheAccess: async (context: TokenCacheContext) => {
      let release!: () => void;
      const previous = tail;
      tail = new Promise<void>((resolve) => { release = resolve; });
      await previous;
      unlock = release;
      let packed: Buffer;
      try {
        packed = await readFile(path);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
        unlock();
        throw error;
      }
      let serialized: string | undefined;
      try {
        if (packed.length < 28) throw new Error('MSAL cache file is invalid');
        const decipher = createDecipheriv('aes-256-gcm', key, packed.subarray(0, 12));
        decipher.setAuthTag(packed.subarray(-16));
        serialized = Buffer.concat([decipher.update(packed.subarray(12, -16)), decipher.final()]).toString('utf8');
      } catch {
        try {
          await unlink(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
            unlock();
            throw error;
          }
        }
      }
      if (serialized !== undefined) {
        try {
          context.tokenCache.deserialize(serialized);
        } catch (error) {
          unlock();
          throw error;
        }
      }
    },
    afterCacheAccess: async (context: TokenCacheContext) => {
      try {
        if (context.cacheHasChanged) {
          const nonce = randomBytes(12);
          const cipher = createCipheriv('aes-256-gcm', key, nonce);
          const ciphertext = Buffer.concat([cipher.update(context.tokenCache.serialize(), 'utf8'), cipher.final()]);
          const packed = Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
          const temp = `${path}.${process.pid}.tmp`;
          await writeFile(temp, packed, { mode: 0o600 });
          await rename(temp, path);
        }
      } finally {
        unlock();
      }
    },
  };

  return new ConfidentialClientApplication({
    auth: {
      clientId: options.clientId,
      authority: `https://login.microsoftonline.com/${options.tenantId}`,
      clientSecret: options.clientSecret,
    },
    cache: { cachePlugin },
  });
}
