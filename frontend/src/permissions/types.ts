export type PermissionSource = 'internal' | 'external';
export type PermissionApi = (path: string, init?: RequestInit) => Promise<Response>;
export type ResourceReference = { schema: string; relation: string };
export type IdentityAttributes = Record<string, string>;

export type Membership = ResourceReference & {
  userColumn: string;
  groupColumn: string;
  activeColumn?: string;
  tenantColumn?: string;
};

export type ReadRule = ResourceReference & {
  label: string;
  fields: string[];
  scope: {
    kind: string;
    column?: string;
    claim?: string;
    membership?: Membership;
  };
  reviewed: boolean;
};

export type PermissionResource = ResourceReference & {
  columns: string[];
  scalarColumns?: string[];
  searchProfile?: {
    id: string;
    keyColumn: string;
    labelColumn: string;
    searchColumns: string[];
    returnColumns: { name: string; type: string }[];
  };
};

export type PermissionPreview = {
  configured: boolean;
  mode?: PermissionSource;
  status?: string;
  userId?: string;
  label?: string;
  rules?: ReadRule[];
  claimColumns?: IdentityAttributes;
  error?: string;
};

export type PermissionResourcePage = {
  resources: PermissionResource[];
  nextSchema?: string;
  nextName?: string;
  error?: string;
};

export type PostgresAuthAdapter = ResourceReference & {
  mode: string;
  permissionSource?: PermissionSource;
  roleLabelAccess?: boolean;
  approvalRecord: string;
  columns?: {
    email: string;
    userId: string;
    role: string;
    active: string;
    tenantId?: string;
    permissionVersion?: string;
  };
  tenantScope?: string;
  roleMappings?: Record<string, string>;
  rules?: ReadRule[];
  claims?: IdentityAttributes;
};

export function resourceKey(resource: ResourceReference): string {
  return JSON.stringify([resource.schema, resource.relation]);
}

export function ruleKey(rule: ReadRule): string {
  return JSON.stringify([rule.label, rule.schema, rule.relation]);
}
