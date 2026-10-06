import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { chmod, mkdir, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { ConfidentialClientApplication } from '@azure/msal-node';

const graphScopes = {
  onedrive: ['https://graph.microsoft.com/Files.Read'],
  sharepoint: ['https://graph.microsoft.com/Sites.Read.All'],
  outlook: ['https://graph.microsoft.com/Mail.Read'],
  teams: ['https://graph.microsoft.com/Chat.Read'],
  teams_channels: [
    'https://graph.microsoft.com/Team.ReadBasic.All',
    'https://graph.microsoft.com/Channel.ReadBasic.All',
    'https://graph.microsoft.com/ChannelMessage.Read.All',
  ],
} as const;
const maxBodyBytes = 16 * 1024;

export type OboResult = { status: number; body: Record<string, string> };

export async function handleOboPayload(msal: ConfidentialClientApplication, payload: unknown): Promise<OboResult> {
  if (typeof payload !== 'object' || payload === null || Object.keys(payload).length !== 2 ||
      !('assertion' in payload) || typeof payload.assertion !== 'string' ||
      !('profile' in payload) || typeof payload.profile !== 'string' || !Object.hasOwn(graphScopes, payload.profile) ||
      payload.assertion.length < 100 || payload.assertion.length > 12_000 ||
      /\s/.test(payload.assertion)) {
    return { status: 400, body: { error: 'invalid_request' } };
  }
  try {
    const token = await msal.acquireTokenOnBehalfOf({
      oboAssertion: payload.assertion,
      scopes: [...graphScopes[payload.profile as keyof typeof graphScopes]],
    });
    if (!token?.accessToken) return { status: 502, body: { error: 'token_exchange_failed' } };
    return { status: 200, body: { accessToken: token.accessToken } };
  } catch {
    return { status: 502, body: { error: 'token_exchange_failed' } };
  }
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += part.length;
    if (size > maxBodyBytes) throw new Error('request_too_large');
    chunks.push(part);
  }
  return Buffer.concat(chunks, size);
}

function respond(response: ServerResponse, status: number, body: unknown): void {
  const data = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': data.length,
    'cache-control': 'no-store',
    connection: 'close',
  });
  response.end(data);
}

export async function startOboSocket(msal: ConfidentialClientApplication, socketPath: string): Promise<() => Promise<void>> {
  await mkdir(dirname(socketPath), { recursive: true, mode: 0o700 });
  await unlink(socketPath).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== 'ENOENT') throw error;
  });

  const server = createServer((request, response) => {
    if (request.method !== 'POST' || request.url !== '/v1/obo' || request.headers['content-type']?.split(';', 1)[0] !== 'application/json') {
      respond(response, 404, { error: 'not_found' });
      return;
    }
    void (async () => {
      let payload: unknown;
      try {
        const data = await readBody(request);
        payload = JSON.parse(data.toString('utf8'));
      } catch (error) {
        respond(response, error instanceof Error && error.message === 'request_too_large' ? 413 : 400,
          { error: error instanceof Error && error.message === 'request_too_large' ? 'request_too_large' : 'invalid_request' });
        return;
      }
      const result = await handleOboPayload(msal, payload);
      respond(response, result.status, result.body);
    })();
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 1_000;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  await chmod(socketPath, 0o600);
  return () => new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      void unlink(socketPath).catch((cleanupError: NodeJS.ErrnoException) => {
        if (cleanupError.code !== 'ENOENT') throw cleanupError;
      }).then(() => resolve(), reject);
    });
  });
}
