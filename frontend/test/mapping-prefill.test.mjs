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


test('metadata aliases prefill arbitrary relation names without treating business email tables as users', () => {
  const current = { mode: 'postgres_role', schema: '', relation: '', approvalRecord: '' };
  const candidate = { schema: 'custom', relation: 'people_directory', ready: false,
    columns: [{name:'id',dataType:'integer'}, {name:'email',dataType:'text'}, {name:'role',dataType:'text'}, {name:'enabled',dataType:'boolean'}] };
  const customer = { ...candidate, relation: 'customers', columns: candidate.columns.filter((field) => field.name !== 'role') };
  const result = authorizationPrefill(current, [candidate, customer], true);
  assert.equal(result.schema, 'custom');
  assert.equal(result.relation, 'people_directory');
  assert.deepEqual(result.columns, { email:'email', userId:'id', role:'role', active:'enabled', tenantId:undefined, permissionVersion:undefined });
  assert.equal(result.approvalRecord, '');
  assert.equal(authorizationPrefill(current, [candidate, {...candidate, relation:'another'}], true), current);
  assert.equal(authorizationPrefill(current, [candidate], false), current);
  assert.equal(authorizationPrefill({...current, schema:'existing'}, [candidate], true).schema, 'existing');
});
