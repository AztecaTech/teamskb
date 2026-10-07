export function candidateColumnMapping(candidate) {
  const fields = candidate.columns ?? [];
  const find = (aliases, boolean = false) => {
    for (const alias of aliases) {
      const matches = fields.filter((field) => field.name.toLowerCase().replaceAll('_', '') === alias && (!boolean || field.dataType === 'boolean'));
      if (matches.length > 1) return undefined;
      if (matches.length === 1) return matches[0].name;
    }
    return undefined;
  };
  const mapping = {
    email: find(['email', 'emailaddress', 'useremail', 'mail', 'primaryemail']),
    userId: find(['userid', 'id', 'accountid']),
    role: find(['databaserole', 'postgresrole', 'dbrole', 'role', 'rolename']),
    active: find(['active', 'isactive', 'enabled'], true),
    tenantId: find(['tenantid', 'organizationid']),
    permissionVersion: find(['permissionversion', 'permissionsversion', 'authversion']),
  };
  return mapping.email && mapping.userId && mapping.role && mapping.active ? mapping : null;
}

export function authorizationPrefill(current, candidates, complete) {
  if (!complete || current.schema || current.relation) return current;
  const ready = candidates.filter((candidate) => candidate.ready);
  const mapped = candidates.filter((candidate) => candidateColumnMapping(candidate));
  const choices = ready.length ? ready : mapped;
  if (choices.length !== 1) return current;
  const candidate = choices[0];
  return { ...current, schema: candidate.schema, relation: candidate.relation,
    ...(candidate.ready ? {} : { columns: candidateColumnMapping(candidate) }) };
}

const quote = (name) => `"${name.replaceAll('"', '""')}"`;
export function queryPrefill(relation, columns) {
  if (!relation.supported) return null;
  const names = new Set(columns.filter((column) => column.schema === relation.schema && column.relation === relation.name).map((column) => column.name));
  if (!['id', 'title', 'content', 'source_url'].every((name) => names.has(name))) return null;
  const base = relation.name.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const id = `${/^[a-z]/.test(base) ? base : `query_${base}`}`.slice(0, 56) + '_search';
  return {
    id,
    description: `Search ${relation.schema}.${relation.name} with the current user's database permissions.`,
    sql: `SELECT "id"::text AS id, "title"::text AS title, "content"::text AS content, "source_url"::text AS source_url FROM ${quote(relation.schema)}.${quote(relation.name)} WHERE (COALESCE("title"::text, '') || ' ' || COALESCE("content"::text, '')) ILIKE '%' || $1 || '%' ORDER BY "id" LIMIT $2`,
  };
}
