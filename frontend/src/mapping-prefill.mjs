export function authorizationPrefill(current, candidates, complete) {
  const ready = candidates.filter((candidate) => candidate.ready);
  if (!complete || ready.length !== 1 || current.schema || current.relation) return current;
  return { ...current, schema: ready[0].schema, relation: ready[0].relation };
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
