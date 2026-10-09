import type { ReadRule } from './ApplicationPermissionEditor';
export function permissionRuleIssues(rule: ReadRule, claims?: Record<string,string>): string[];
type Metadata = { relations: Array<{schema:string;name:string;supported:boolean}>; columns: Array<{schema:string;relation:string;name:string;dataType:string}>; keys: Array<{schema:string;relation:string;kind:string;columns:string[]}> };
export function businessProfilePrefill(page: Metadata, schema:string, relation:string, existingIds?:string[]): { error?:string; draft?:{id:string;label:string;key:string;display:string;searchColumns:string[];returnTypes:Record<string,string>} };
