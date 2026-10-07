type Candidate = { schema: string; relation: string; ready: boolean };
export function authorizationPrefill<T extends { schema: string; relation: string }>(current: T, candidates: Candidate[], complete: boolean): T;
export function queryPrefill(relation: { schema: string; name: string; supported: boolean }, columns: Array<{ schema: string; relation: string; name: string }>): { id: string; description: string; sql: string } | null;
