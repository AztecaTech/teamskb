import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { handleOboPayload, startOboSocket } from '../dist/obo.js';

function post(socketPath, value) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(value));
    const req = request({ socketPath, path: '/v1/obo', method: 'POST', headers: {
      'content-type': 'application/json', 'content-length': body.length,
    } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('exchanges only the fixed delegated Graph scope for each named profile', async () => {
  let exchange;
  const result = await handleOboPayload({ acquireTokenOnBehalfOf: async (request) => {
    exchange = request;
    return { accessToken: 'graph-token' };
  } }, { assertion: 'a'.repeat(100), profile: 'onedrive' });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { accessToken: 'graph-token' });
  assert.equal(exchange.oboAssertion, 'a'.repeat(100));
  assert.deepEqual(exchange.scopes, ['https://graph.microsoft.com/Files.Read']);

  const sharepoint = await handleOboPayload({ acquireTokenOnBehalfOf: async (request) => {
    exchange = request;
    return { accessToken: 'graph-token' };
  } }, { assertion: 'a'.repeat(100), profile: 'sharepoint' });
  assert.equal(sharepoint.status, 200);
  assert.deepEqual(exchange.scopes, ['https://graph.microsoft.com/Sites.Read.All']);

  const outlook = await handleOboPayload({ acquireTokenOnBehalfOf: async (request) => {
    exchange = request;
    return { accessToken: 'graph-token' };
  } }, { assertion: 'a'.repeat(100), profile: 'outlook' });
  assert.equal(outlook.status, 200);
  assert.deepEqual(exchange.scopes, ['https://graph.microsoft.com/Mail.Read']);

  const teams = await handleOboPayload({ acquireTokenOnBehalfOf: async (request) => {
    exchange = request;
    return { accessToken: 'graph-token' };
  } }, { assertion: 'a'.repeat(100), profile: 'teams' });
  assert.equal(teams.status, 200);
  assert.deepEqual(exchange.scopes, ['https://graph.microsoft.com/Chat.Read']);

  const teamsChannels = await handleOboPayload({ acquireTokenOnBehalfOf: async (request) => {
    exchange = request;
    return { accessToken: 'graph-token' };
  } }, { assertion: 'a'.repeat(100), profile: 'teams_channels' });
  assert.equal(teamsChannels.status, 200);
  assert.deepEqual(exchange.scopes, [
    'https://graph.microsoft.com/Team.ReadBasic.All',
    'https://graph.microsoft.com/Channel.ReadBasic.All',
    'https://graph.microsoft.com/ChannelMessage.Read.All',
  ]);
});

test('rejects caller-selected scopes and malformed assertions', async () => {
  let called = false;
  const msal = { acquireTokenOnBehalfOf: async () => { called = true; return { accessToken: 'unused' }; } };
  const extraScope = await handleOboPayload(msal, { assertion: 'a'.repeat(100), profile: 'onedrive', scopes: ['Mail.Read'] });
  const unknownProfile = await handleOboPayload(msal, { assertion: 'a'.repeat(100), profile: 'mail' });
  const inheritedProfile = await handleOboPayload(msal, { assertion: 'a'.repeat(100), profile: 'constructor' });
  const shortAssertion = await handleOboPayload(msal, { assertion: 'not-a-token', profile: 'onedrive' });
  assert.equal(extraScope.status, 400);
  assert.equal(unknownProfile.status, 400);
  assert.equal(inheritedProfile.status, 400);
  assert.deepEqual(extraScope.body, { error: 'invalid_request' });
  assert.equal(shortAssertion.status, 400);
  assert.equal(called, false);
});

test('does not return MSAL error details', async () => {
  const result = await handleOboPayload({ acquireTokenOnBehalfOf: async () => { throw new Error('sensitive tenant response'); } }, { assertion: 'a'.repeat(100), profile: 'onedrive' });
  assert.equal(result.status, 502);
  assert.deepEqual(result.body, { error: 'token_exchange_failed' });
});

test('serves OBO over a private Unix socket', { skip: process.platform === 'win32' && 'Unix sockets require Linux' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'iqkb-obo-'));
  const socketPath = join(dir, 'obo.sock');
  const close = await startOboSocket({ acquireTokenOnBehalfOf: async () => ({ accessToken: 'graph-token' }) }, socketPath);
  try {
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    const response = await post(socketPath, { assertion: 'a'.repeat(100), profile: 'onedrive' });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { accessToken: 'graph-token' });
  } finally {
    await close();
    await rm(dir, { recursive: true, force: true });
  }
});
