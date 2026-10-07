const normalize = (value) => value.toLowerCase().replaceAll('_', '');
const sensitive = (name) => /password|secret|token|backupcode/.test(normalize(name));
const audit = (name) => ['createdby', 'updatedby', 'deletedby', 'changedby', 'archivedby'].includes(normalize(name));

// Suggestions never constitute permission evidence or deployment approval.
// Preserve edited drafts; only an empty label draft receives suggestions.
export function suggestPermissionDrafts(drafts, resources, relationships, identity) {
  const existingCount = drafts.reduce((count, draft) => count + draft.resources.length, 0);
  const emptyCount = drafts.filter((draft) => draft.resources.length === 0).length;
  const perLabel = emptyCount ? Math.min(25, Math.floor(Math.max(0, 100 - existingCount) / emptyCount)) : 0;
  const candidates = resources.filter((resource) => !sensitive(resource.relation) && !(resource.schema === identity.schema && resource.relation === identity.relation));
  return drafts.map((draft) => {
    if (draft.resources.length) return draft;
    const rules = candidates.map((resource) => {
      const fields = resource.columns.filter((name) => !sensitive(name)).slice(0, 32);
      const links = relationships.filter((link) => link.sourceSchema === resource.schema && link.sourceRelation === resource.relation && link.targetSchema === identity.schema && link.targetRelation === identity.relation && link.sourceColumns.length === 1 && link.targetColumns.length === 1 && link.targetColumns[0] === identity.userId && !audit(link.sourceColumns[0]));
      const userColumns = [...new Set(links.map((link) => link.sourceColumns[0]))];
      const userColumn = userColumns.length === 1 && !sensitive(userColumns[0]) ? userColumns[0] : undefined;
      if (userColumn && !fields.includes(userColumn)) { if (fields.length === 32) fields.pop(); fields.push(userColumn); }
      return { schema: resource.schema, relation: resource.relation, fields, scope: userColumn ? 'user' : 'pending', ...(userColumn ? { userColumn } : {}), reviewed: false };
    }).filter((rule) => rule.fields.length).sort((a, b) => Number(b.scope === 'user') - Number(a.scope === 'user')).slice(0, perLabel);
    return { ...draft, resources: rules };
  });
}
