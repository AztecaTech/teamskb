type Candidate = { schema: string; relation: string; ready: boolean; columns?: { name: string; dataType: string }[] };
export function authorizationPrefill<T extends { schema: string; relation: string }>(current: T, candidates: Candidate[], complete: boolean): T;
export function queryPrefill(relation: { schema: string; name: string; supported: boolean }, columns: Array<{ schema: string; relation: string; name: string }>): { id: string; description: string; sql: string } | null;

export function candidateColumnMapping(candidate: Candidate): { email: string; userId: string; role: string; active: string; tenantId?: string; permissionVersion?: string } | null;
