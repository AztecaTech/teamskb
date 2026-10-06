import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import express from 'express';
import { App, ExpressAdapter } from '@microsoft/teams.apps';
import { createMsalClient } from './token-cache.js';
import { startOboSocket } from './obo.js';
import { createBotMessageHandler } from './bot-message.js';

const port = Number(process.env.PORT ?? '3978');
const botEnabled = process.env.BOT_ENABLED !== 'false';
const tenantId = process.env.TENANT_ID;
const botClientId = process.env.BOT_CLIENT_ID;
const appClientId = process.env.APP_CLIENT_ID;
const teamsAppId = process.env.TEAMS_APP_ID;
const publicOrigin = process.env.PUBLIC_ORIGIN;
const oauthConnectionName = process.env.OAUTH_CONNECTION_NAME ?? 'iqkbteams';
if (!tenantId || !appClientId) throw new Error('tenant and API client IDs are required');
if (botEnabled && (!botClientId || !teamsAppId || !publicOrigin)) throw new Error('bot client ID, Teams app ID and public origin are required');
const botSecretFile = process.env.BOT_CLIENT_SECRET_FILE;
const appSecretFile = process.env.APP_CLIENT_SECRET_FILE;
const botSecret = !botEnabled ? undefined : botSecretFile ? (await readFile(botSecretFile, 'utf8')).trim() : process.env.BOT_CLIENT_SECRET?.trim();
const appSecret = appSecretFile ? (await readFile(appSecretFile, 'utf8')).trim() : process.env.APP_CLIENT_SECRET?.trim();
if (!appSecret || (botEnabled && !botSecret)) throw new Error('Entra client secrets are required');
const msal = await createMsalClient({
  clientId: appClientId,
  tenantId,
  clientSecret: appSecret,
  cacheKeyFile: process.env.MSAL_CACHE_KEY_FILE ?? '',
  ...(process.env.MSAL_CACHE_KEY_HEX ? { cacheKeyHex: process.env.MSAL_CACHE_KEY_HEX } : {}),
});
const closeOboSocket = await startOboSocket(msal, process.env.OBO_SOCKET ?? '/run/iqkb/obo.sock');

const web = express();
const server = createServer(web);
if (botEnabled) {
  process.env.CLIENT_ID = botClientId!;
  process.env.CLIENT_SECRET = botSecret!;
  const adapter = new ExpressAdapter(server);
  const app = new App({ httpServerAdapter: adapter, oauth: { defaultConnectionName: oauthConnectionName } });
  app.on('message', createBotMessageHandler(teamsAppId!, publicOrigin!));
  await app.initialize();
}
server.listen(port, process.env.HTTP_LISTEN_HOST ?? '0.0.0.0');

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => server.close(() => {
    void closeOboSocket().finally(() => process.exit(0));
  }));
}
