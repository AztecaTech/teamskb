export function permissionRuleIssues(rule, claims = {}) {
  const issues = [];
  if (!rule.fields?.length) issues.push('Select at least one readable field.');
  if (!['all', 'user', 'email', 'claim', 'membership'].includes(rule.scope?.kind)) issues.push('Choose the row access this label has in the native application.');
  if (['user', 'email', 'claim', 'membership'].includes(rule.scope?.kind) && !rule.scope.column) issues.push('Select the resource column used to restrict rows.');
  if (rule.scope?.kind === 'claim' && !claims[rule.scope.claim]) issues.push('Map and select the user attribute for this row rule.');
  if (rule.scope?.kind === 'membership') {
    const membership = rule.scope.membership;
    if (!membership?.schema || !membership.relation || !membership.userColumn || !membership.groupColumn) issues.push('Select the existing membership table and its user and group columns.');
  }
  return issues;
}

const textTypes = new Set(['text', 'character varying', 'character', 'name', 'uuid']);
const keyTypes = new Set([...textTypes,'smallint','integer','bigint']);
const columnType = (type) => textTypes.has(type) ? 'text' : ({ smallint: 'integer', integer: 'integer', bigint: 'integer', numeric: 'number', real: 'number', 'double precision': 'number', boolean: 'boolean', date: 'date', 'timestamp without time zone': 'timestamp', 'timestamp with time zone': 'timestamp' })[type];

// Suggest a query draft only from metadata already filtered by the saved adapter.
// No role meaning, row scope, field permission or uniqueness is invented here.
export function businessProfilePrefill(page, schema, relation, existingIds = []) {
  const table = page.relations.find((item) => item.schema === schema && item.name === relation && item.supported);
  if (!table) return { error: 'This resource has no supported search metadata for your saved permissions.' };
  const columns = page.columns.filter((item) => item.schema === schema && item.relation === relation);
  const names = new Set(columns.filter((item)=>keyTypes.has(item.dataType)).map((item) => item.name));
  const keys = [...new Set(page.keys.filter((item) => item.schema === schema && item.relation === relation && item.columns.length === 1 && names.has(item.columns[0])).map((item) => item.columns[0]))];
  const primary = page.keys.find((item) => item.schema === schema && item.relation === relation && item.kind === 'primary' && item.columns.length === 1 && names.has(item.columns[0]));
  const key = primary?.columns[0] || (keys.length === 1 ? keys[0] : '');
  if (!key) return { error: 'Select an existing single-column unique key in the search profile. Include that column in the readable fields; the app will not create a key.' };
  const text = columns.filter((item) => textTypes.has(item.dataType) && item.name !== key);
  if (!text.length) return { error: 'Include a readable text column for the display name and search terms in this resource rule.' };
  const display = text[0].name;
  const returned = columns.filter((item) => item.name !== key && columnType(item.dataType)).slice(0, 12);
  const base = `${schema}_${relation}`.toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 44);
  const stem = `${/^[a-z]/.test(base) ? base : `resource_${base}`}`.slice(0, 50);
  let id = `${stem}_search`;
  for (let version = 2; existingIds.includes(id); version++) id = `${stem}_search_${version}`;
  return { draft: { id, label: relation.replaceAll('_', ' '), key, display, searchColumns: text.slice(0, 12).map((item) => item.name), returnTypes: Object.fromEntries(returned.map((item) => [item.name, columnType(item.dataType)])) } };
}
