import test from 'node:test';
import assert from 'node:assert/strict';
import { createBotMessageHandler } from '../dist/bot-message.js';

const ids = {
  app: '12345678-1234-4234-9234-123456789abc',
  token: 'not-a-real-token',
  origin: 'https://assistant.example.com',
};

function context(conversationType, text = 'find policy') {
  const sent = [];
  let signIns = 0;
  return {
    sent,
    get signIns() { return signIns; },
    activity: { conversation: { conversationType }, text },
    async signin() { signIns++; return ids.token; },
    async send(message) { sent.push(message); },
  };
}

test('group and channel messages receive a private tab handoff without sign-in or fetch', async () => {
  for (const kind of ['groupChat', 'channel']) {
    const ctx = context(kind);
    let fetched = false;
    await createBotMessageHandler(ids.app, ids.origin, async () => { fetched = true; throw new Error('unexpected fetch'); })(ctx);
    assert.equal(ctx.signIns, 0);
    assert.equal(fetched, false);
    assert.match(ctx.sent[0], /ask privately/);
  }
});

test('personal chat authenticates then returns the answer and citations', async () => {
  const ctx = context('personal', '  find policy  ');
  let request;
  const fetcher = async (url, options) => {
    request = { url, options };
    return Response.json({ answer: 'Use the retention policy.', sources: [{ name: 'Policy.docx', url: 'https://tenant.sharepoint.com/policy' }] });
  };
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  assert.equal(ctx.signIns, 1);
  assert.equal(request.url, 'http://app:8080/api/ask');
  assert.equal(request.options.headers.authorization, `Bearer ${ids.token}`);
  assert.equal(JSON.parse(request.options.body).question, 'find policy');
  assert.match(ctx.sent[0], /Use the retention policy/);
  assert.match(ctx.sent[0], /Policy\.docx: https:\/\/tenant\.sharepoint\.com\/policy/);
});

test('personal chat renders entity clarification candidates', async () => {
  const ctx = context('personal');
  const fetcher = async () => Response.json({ clarification: { kind: 'ambiguous_entity', question: 'Which customer?', candidates: [
    { id: 'cust-1', displayName: 'Northwind' }, { id: 'cust-2', displayName: 'Contoso' },
  ] }, sources: [] });
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  assert.match(ctx.sent[0], /Which customer\?/);
  assert.match(ctx.sent[0], /Northwind \(cust-1\)/);
  assert.match(ctx.sent[0], /Contoso \(cust-2\)/);
});

test('personal chat preserves all six API citations', async () => {
  const ctx = context('personal');
  const sources = Array.from({ length: 6 }, (_, index) => ({ name: `Source ${index + 1}`, url: '' }));
  await createBotMessageHandler(ids.app, ids.origin, async () => Response.json({ answer: 'Answer', sources }))(ctx);
  assert.match(ctx.sent[0], /Source 6/);
});

test('personal chat caps the complete reply by UTF-8 bytes without splitting characters', async () => {
  const ctx = context('personal');
  const fetcher = async () => Response.json({ answer: '🙂'.repeat(20_000), sources: [{ name: 'Source', url: 'https://example.com' }] });
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  const reply = ctx.sent[0];
  assert.ok(new TextEncoder().encode(reply).length <= 20_000);
  assert.equal(reply.charCodeAt(reply.length - 1), 0xDE42);
});

test('personal chat does not submit without a sign-in token', async () => {
  const ctx = context('personal');
  ctx.signin = async () => undefined;
  let fetched = false;
  await createBotMessageHandler(ids.app, ids.origin, async () => { fetched = true; })(ctx);
  assert.equal(fetched, false);
  assert.deepEqual(ctx.sent, []);
});

test('personal chat returns a generic error without leaking API details', async () => {
  const ctx = context('personal');
  await createBotMessageHandler(ids.app, ids.origin, async () => new Response('private upstream detail', { status: 503 }))(ctx);
  assert.equal(ctx.sent.length, 1);
  assert.doesNotMatch(ctx.sent[0], /private upstream detail/);
});

test('personal chat omits unsafe or deceptive source URLs', async () => {
  const ctx = context('personal');
  const fetcher = async () => Response.json({ answer: 'Answer [S1]', sources: [
    { name: 'Unsafe scheme', url: 'javascript:alert(1)' },
    { name: 'Deceptive userinfo', url: 'https://trusted.example@attacker.example/path' },
  ] });
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  assert.match(ctx.sent[0], /Unsafe scheme/);
  assert.match(ctx.sent[0], /Deceptive userinfo/);
  assert.doesNotMatch(ctx.sent[0], /javascript:|attacker\.example/);
});

test('personal chat neutralizes Markdown and URLs in source names', async () => {
  const ctx = context('personal');
  const fetcher = async () => Response.json({ answer: 'Answer [S1]', sources: [
    { name: '[Policy](https://attacker.example) https://other.example/file', url: '' },
  ] });
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  assert.match(ctx.sent[0], /Policy/);
  assert.match(ctx.sent[0], /link omitted/);
  assert.doesNotMatch(ctx.sent[0], /attacker\.example|other\.example|\]\(/);
});

test('personal chat removes model-provided links and keeps source citations', async () => {
  const ctx = context('personal');
  const fetcher = async () => Response.json({ answer: 'Read [the link](https://attacker.example) or https://other.example. [S1]', sources: [
    { name: 'Approved policy', url: 'https://tenant.example/policy' },
  ] });
  await createBotMessageHandler(ids.app, ids.origin, fetcher)(ctx);
  assert.match(ctx.sent[0], /the link/);
  assert.match(ctx.sent[0], /\[link omitted\]/);
  assert.match(ctx.sent[0], /Approved policy: https:\/\/tenant\.example\/policy/);
  assert.doesNotMatch(ctx.sent[0], /attacker\.example|other\.example/);
});
