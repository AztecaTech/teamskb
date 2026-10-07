import test from 'node:test';
import assert from 'node:assert/strict';
import { suggestPermissionDrafts } from '../src/permission-suggestions.mjs';

test('suggestions are label-independent, exclude credentials and never approve access', () => {
  const identity = { schema: 's', relation: 'people', userId: 'key' };
  const resources = [{schema:'s',relation:'password_reset_tokens',columns:['id','owner']},{schema:'s',relation:'people',columns:['key','password']},{schema:'s',relation:'records',columns:['id','owner','created_by','title','refreshTokenHash']}];
  const link = { sourceSchema:'s',sourceRelation:'records',sourceColumns:['owner'],targetSchema:'s',targetRelation:'people',targetColumns:['key'] };
  const result=suggestPermissionDrafts(['arbitrary-a','arbitrary-b'].map((label)=>({label,executionRole:'r',resources:[]})),resources,[link],identity);
  assert.deepEqual(result[0].resources,result[1].resources);
  assert.equal(result[0].resources.length,1);assert.equal(result[0].resources[0].scope,'user');assert.equal(result[0].resources[0].reviewed,false);
  assert.ok(!result[0].resources[0].fields.includes('refreshTokenHash'));
  const audit=suggestPermissionDrafts([{label:'x',executionRole:'r',resources:[]}],resources,[{...link,sourceColumns:['created_by']}],identity);
  assert.equal(audit[0].resources[0].scope,'pending');
  const edited={label:'x',executionRole:'r',resources:[{schema:'manual',relation:'rules',fields:['id'],scope:'all',reviewed:true}]};
  assert.equal(suggestPermissionDrafts([edited],resources,[link],identity)[0],edited);
});

test('ambiguous user links remain unresolved and generation respects rule limits',()=>{
  const identity={schema:'s',relation:'people',userId:'id'};
  const resources=Array.from({length:80},(_,i)=>({schema:'s',relation:`table${i}`,columns:['id','first','second']}));
  const base={sourceSchema:'s',sourceRelation:'table0',targetSchema:'s',targetRelation:'people',targetColumns:['id']};
  const result=suggestPermissionDrafts(Array.from({length:10},(_,i)=>({label:`label${i}`,executionRole:`role${i}`,resources:[]})),resources,[{...base,sourceColumns:['first']},{...base,sourceColumns:['second']}],identity);
  assert.equal(result[0].resources[0].scope,'pending');assert.equal(result.flatMap((draft)=>draft.resources).length,100);
});
