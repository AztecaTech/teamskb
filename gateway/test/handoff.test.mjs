import assert from 'node:assert/strict';
import test from 'node:test';
import { privateHandoffMessage, sendPrivateHandoff } from '../dist/handoff.js';

const teamsAppId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

test('builds a personal-tab deep link without carrying conversation text', () => {
  const message = privateHandoffMessage(teamsAppId, 'https://knowledge.example.test');
  const match = message.match(/\((https:\/\/[^)]+)\)/);
  assert.ok(match);
  const link = new URL(match[1]);
  assert.equal(link.origin, 'https://teams.microsoft.com');
  assert.equal(link.pathname, `/l/entity/${teamsAppId}/assistant`);
  assert.equal(link.searchParams.get('webUrl'), 'https://knowledge.example.test');
  assert.equal(link.searchParams.get('label'), 'IQ Knowledge Assistant');
  assert.doesNotMatch(message, /question|activity|source|secret/i);
});

test('rejects invalid app IDs and non-origin public URLs', () => {
  for (const [id, origin] of [
    ['not-a-guid', 'https://knowledge.example.test'],
    [teamsAppId, 'http://knowledge.example.test'],
    [teamsAppId, 'https://knowledge.example.test/path'],
    [teamsAppId, 'https://user:pass@knowledge.example.test'],
  ]) {
    assert.throws(() => privateHandoffMessage(id, origin));
  }
});

test('message handler sends the same content-free handoff', async () => {
  const sent = [];
  await sendPrivateHandoff(async (message) => sent.push(message), teamsAppId, 'https://knowledge.example.test');
  assert.equal(sent.length, 1);
  assert.equal(sent[0], privateHandoffMessage(teamsAppId, 'https://knowledge.example.test'));
});
