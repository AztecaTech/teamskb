type Rule = { schema: string; relation: string; fields: string[]; scope: 'pending' | 'all' | 'user'; userColumn?: string; reviewed: boolean };
type Draft = { label: string; executionRole: string; resources: Rule[] };
export function suggestPermissionDrafts(drafts: Draft[], resources: { schema: string; relation: string; columns: string[] }[], relationships: { sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] }[], identity: { schema: string; relation: string; userId: string }): Draft[];
