import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeRelationChoice, encodeRelationChoice } from '../src/relation-choice.mjs';

test('relation choices preserve periods and quotes inside identifiers', () => {
  const schema = 'tenant.region';
  const relation = 'asset."history.v2"';
  assert.deepEqual(decodeRelationChoice(encodeRelationChoice(schema, relation)), [schema, relation]);
});

test('malformed relation choices are rejected', () => {
  assert.equal(decodeRelationChoice('public.assets'), null);
  assert.equal(decodeRelationChoice('["only-one"]'), null);
});
