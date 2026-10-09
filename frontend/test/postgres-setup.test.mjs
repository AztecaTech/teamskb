import assert from 'node:assert/strict';
import test from 'node:test';
import { businessProfilePrefill, permissionRuleIssues } from '../src/postgres-setup.mjs';

test('review requires complete field and row rules, including claims and memberships', () => {
  assert.equal(permissionRuleIssues({ fields: [], scope: { kind: 'pending' } }).length, 2);
  assert.equal(permissionRuleIssues({ fields: ['custom_field'], scope: { kind: 'user' } }).length, 1);
  assert.equal(permissionRuleIssues({ fields: ['custom_field'], scope: { kind: 'claim', column: 'owner', claim: 'native_name' } }).length, 1);
  assert.deepEqual(permissionRuleIssues({ fields: ['custom_field'], scope: { kind: 'claim', column: 'owner', claim: 'native_name' } }, { native_name: 'name' }), []);
  assert.equal(permissionRuleIssues({ fields: ['custom_field'], scope: { kind: 'membership', column: 'group', membership: { schema: 'custom' } } }).length, 1);
  assert.deepEqual(permissionRuleIssues({ fields: ['custom_field'], scope: { kind: 'all' } }), []);
});

const metadata = () => ({ relations: [{schema:'custom',name:'arbitrary_records',supported:true}], columns: [{schema:'custom',relation:'arbitrary_records',name:'record_key',dataType:'integer'}, {schema:'custom',relation:'arbitrary_records',name:'caption',dataType:'text'}, {schema:'custom',relation:'arbitrary_records',name:'amount',dataType:'numeric'}], keys: [{schema:'custom',relation:'arbitrary_records',kind:'primary',columns:['record_key']}] });

test('profile suggestions use existing metadata and avoid overwriting saved profiles', () => {
  const result = businessProfilePrefill(metadata(),'custom','arbitrary_records',['custom_arbitrary_records_search']);
  assert.equal(result.draft.id,'custom_arbitrary_records_search_2');
  assert.equal(result.draft.key,'record_key');
  assert.equal(result.draft.display,'caption');
  assert.deepEqual(result.draft.searchColumns,['caption']);
  assert.deepEqual(result.draft.returnTypes,{caption:'text',amount:'number'});
  assert.equal(result.draft.scope,undefined);
  assert.equal(result.draft.reviewed,undefined);
});

test('profile suggestions cannot invent keys or access unavailable fields and relations', () => {
  const page=metadata();page.keys=[];
  assert.match(businessProfilePrefill(page,'custom','arbitrary_records').error,/unique key/);
  page.keys=[{schema:'custom',relation:'arbitrary_records',kind:'primary',columns:['hidden_key']}];
  assert.match(businessProfilePrefill(page,'custom','arbitrary_records').error,/readable fields/);
  assert.match(businessProfilePrefill(metadata(),'custom','hidden_records').error,/saved permissions/);
  const withoutText=metadata();withoutText.columns=withoutText.columns.filter((column)=>column.name!=='caption');
  assert.match(businessProfilePrefill(withoutText,'custom','arbitrary_records').error,/readable text column/);
  const unsupportedKey=metadata();unsupportedKey.columns[0].dataType='numeric';
  assert.match(businessProfilePrefill(unsupportedKey,'custom','arbitrary_records').error,/unique key/);
});
