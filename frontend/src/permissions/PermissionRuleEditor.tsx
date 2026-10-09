import { permissionRuleIssues } from '../postgres-setup.mjs';
import type { IdentityAttributes, Membership, PermissionResource, ReadRule } from './types';

type Props = {
  rule: ReadRule;
  resource?: PermissionResource;
  claims: IdentityAttributes;
  initiallyOpen: boolean;
  isCurrentLabel: boolean;
  onUpdate: (change: Partial<ReadRule>) => void;
  onRemove: () => void;
  onSelect: () => void;
};

const membershipFields = [
  ['schema', 'Membership schema'],
  ['relation', 'Membership table'],
  ['userColumn', 'Member user-ID column'],
  ['groupColumn', 'Group-ID column'],
  ['activeColumn', 'Active boolean column (optional)'],
  ['tenantColumn', 'Microsoft tenant-ID column (optional)'],
] as const;

function MembershipFields({ value, onChange }: {
  value?: Membership;
  onChange: (value: Membership) => void;
}) {
  return <div>
    <p>Map an existing membership relation. Its user ID must match the stable database user ID. The group ID must match the resource scope column.</p>
    {membershipFields.map(([key, label]) => <label key={key}>
      {label}
      <input
        value={value?.[key] || ''}
        maxLength={63}
        onChange={(event) => onChange({
          schema: '', relation: '', userColumn: '', groupColumn: '',
          ...value, [key]: event.target.value,
        })}
      />
    </label>)}
  </div>;
}

export default function PermissionRuleEditor({
  rule, resource, claims, initiallyOpen, isCurrentLabel, onUpdate, onRemove, onSelect,
}: Props) {
  const fields = resource?.scalarColumns || rule.fields;
  const issues = permissionRuleIssues(rule, claims);
  const needsScopeColumn = !['all', 'pending'].includes(rule.scope.kind);

  return <details className="query-entry" open={initiallyOpen || !rule.reviewed || undefined}>
    <summary>
      {rule.schema}.{rule.relation} · {rule.fields.length} fields · {rule.scope.kind} · {rule.reviewed ? 'reviewed' : 'review needed'}
    </summary>
    <p>Readable scalar fields (up to 32). Include the fields needed for search, the unique key and display name. Structured JSON, credential fields and custom types are excluded.</p>
    {fields.map((column) => <label className="check" key={column}>
      <input
        type="checkbox"
        checked={rule.fields.includes(column)}
        disabled={!rule.fields.includes(column) && rule.fields.length >= 32}
        onChange={(event) => onUpdate({
          fields: event.target.checked
            ? [...rule.fields, column]
            : rule.fields.filter((name) => name !== column),
        })}
      />
      {column}
    </label>)}
    {!resource && <p>Load the resource's metadata page to edit its fields.</p>}
    <label>
      Row scope
      <select value={rule.scope.kind} onChange={(event) => onUpdate({ scope: { kind: event.target.value } })}>
        <option value="pending">Select a verified rule</option>
        <option value="all">All rows in this reviewed resource</option>
        <option value="user">Matches the database user ID</option>
        <option value="email">Matches the verified email</option>
        <option value="claim">Matches a mapped user attribute</option>
        <option value="membership">Matches existing team/group membership</option>
      </select>
    </label>
    {needsScopeColumn && <label>
      Resource scope column
      <select value={rule.scope.column || ''} onChange={(event) => onUpdate({ scope: { ...rule.scope, column: event.target.value } })}>
        <option value="">Select column</option>
        {fields.map((column) => <option key={column} value={column}>{column}</option>)}
      </select>
    </label>}
    {rule.scope.kind === 'claim' && <label>
      Matched user attribute
      <select value={rule.scope.claim || ''} onChange={(event) => onUpdate({ scope: { ...rule.scope, claim: event.target.value } })}>
        <option value="">Select mapped attribute</option>
        {Object.keys(claims).map((name) => <option key={name}>{name}</option>)}
      </select>
    </label>}
    {rule.scope.kind === 'membership' && <MembershipFields
      value={rule.scope.membership}
      onChange={(membership) => onUpdate({ scope: { ...rule.scope, membership } })}
    />}
    {issues.length > 0 && <div role="status">
      <strong>To complete this resource:</strong>
      <ul>{issues.map((issue) => <li key={issue}>{issue}</li>)}</ul>
    </div>}
    <label className="check">
      <input
        type="checkbox"
        checked={rule.reviewed}
        disabled={issues.length > 0}
        onChange={(event) => onUpdate({ reviewed: event.target.checked })}
      />
      These fields and this row access match the native application's existing permissions
    </label>
    {rule.reviewed && isCurrentLabel && <button type="button" onClick={onSelect}>
      Use this resource for the first search profile
    </button>}
    <button type="button" onClick={onRemove}>Remove resource rule</button>
  </details>;
}
