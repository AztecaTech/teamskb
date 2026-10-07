import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizationPrefill, queryPrefill } from '../src/mapping-prefill.mjs';

test('only one complete compatible mapping prefills an empty draft without inventing approval', () => {
  const current = { mode: 'session_context', schema: '', relation: '', approvalRecord: '' };
  const candidate = { ready: true, schema: 'auth', relation: 'members' };
  assert.deepEqual(authorizationPrefill(current, [candidate], true), { ...current, schema: 'auth', relation: 'members' });
  assert.equal(authorizationPrefill(current, [candidate], false), current);
  assert.equal(authorizationPrefill(current, [candidate, { ...candidate, relation: 'other' }], true), current);
  assert.equal(authorizationPrefill(current, [{ ...candidate, ready: false }], true), current);
  const existing = { ...current, schema: 'manual' };
  assert.equal(authorizationPrefill(existing, [candidate], true), existing);
});

test('query draft requires all contract columns and quotes metadata identifiers', () => {
  const relation = { schema: 'schema"name', name: 'Policy.Docs', supported: true };
  const columns = ['id', 'title', 'content', 'source_url'].map((name) => ({ schema: relation.schema, relation: relation.name, name }));
  const draft = queryPrefill(relation, columns);
  assert.equal(draft.id, 'policy_docs_search');
  assert.ok(draft.sql.includes('FROM "schema""name"."Policy.Docs"'));
  assert.ok(draft.sql.includes("ILIKE '%' || $1 || '%'"));
  assert.ok(draft.sql.endsWith('LIMIT $2'));
  assert.equal(queryPrefill({ ...relation, supported: false }, columns), null);
  assert.equal(queryPrefill(relation, columns.slice(0, 3)), null);
});
