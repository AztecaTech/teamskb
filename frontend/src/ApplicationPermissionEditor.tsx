import { useEffect, useState } from 'react';

export type Membership = { schema: string; relation: string; userColumn: string; groupColumn: string; activeColumn?: string; tenantColumn?: string };
export type ReadRule = { label: string; schema: string; relation: string; fields: string[]; scope: { kind: string; column?: string; claim?: string; membership?: Membership }; reviewed: boolean };
type Resource = { schema: string; relation: string; columns: string[]; scalarColumns?: string[] };
type Props = { labels: string[]; rules: ReadRule[]; claims: Record<string, string>; identity: { schema: string; relation: string }; disabled: boolean; onChange: (rules: ReadRule[], claims: Record<string, string>) => void; api: (path: string, init?: RequestInit) => Promise<Response> };

export default function ApplicationPermissionEditor({ labels, rules, claims, identity, disabled, onChange, api }: Props) {
  const [resources, setResources] = useState<Resource[]>([]);
  const [cursor, setCursor] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [claimName, setClaimName] = useState('');
  const [claimColumn, setClaimColumn] = useState('');
  async function load(append = false) {
    setBusy(true);
    try {
      const response = await api(`/api/admin/postgres/auth/resources${append ? cursor : ''}`);
      const page = await response.json() as { resources: Resource[]; nextSchema?: string; nextName?: string; error?: string };
      if (!response.ok) throw new Error(`Resource discovery failed (${page.error || 'unknown'}).`);
      setResources((current) => append ? [...current, ...page.resources] : page.resources);
      setCursor(page.nextSchema ? `?afterSchema=${encodeURIComponent(page.nextSchema)}&afterName=${encodeURIComponent(page.nextName || '')}` : '');
      setMessage('Metadata loaded. Select permissions that match the native application. No table rows or database changes are involved.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Resource discovery failed.'); }
    finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);
  function update(index: number, change: Partial<ReadRule>) { onChange(rules.map((rule, position) => position === index ? { ...rule, ...change, reviewed: change.reviewed ?? false } : rule), claims); }
  const identityResource = resources.find((resource) => resource.schema === identity.schema && resource.relation === identity.relation);
  const detectedLabels = [...new Set([...labels, ...rules.map((rule) => rule.label)])];
  return <div id="application-permissions" className="query-entry"><h4>Application permission adapter</h4>
    <p>These rules control only IQ Knowledge reads. Review them against the native application's existing permissions. A label never grants access by its name. JSON visibility, computed fields and custom backend rules require an adapter extension and remain unsupported here.</p>
    <fieldset disabled={disabled || busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <div className="button-row"><button type="button" onClick={() => void load()}>Refresh resource metadata</button>{cursor && <button type="button" onClick={() => void load(true)}>Load more resources</button>}</div>
      {message && <p role="status">{message}</p>}
      <details><summary>Additional identity attributes (optional)</summary><p>For rules based on a native user name or organization ID, map an attribute to an existing column in the user relation. Values are read from the matched user, never entered by the search user.</p>
        {Object.entries(claims).map(([name, column]) => <p key={name}>{name} → {column} <button type="button" onClick={() => { const next = { ...claims }; delete next[name]; onChange(rules.map((rule) => rule.scope.claim === name ? { ...rule, reviewed: false } : rule), next); }}>Remove attribute</button></p>)}
        <label>Attribute name<input value={claimName} maxLength={63} onChange={(event) => setClaimName(event.target.value)} placeholder="Choose an attribute name" /></label>
        <label>Existing user column{identityResource ? <select value={claimColumn} onChange={(event) => setClaimColumn(event.target.value)}><option value="">Select column</option>{identityResource.scalarColumns?.map((column) => <option key={column} value={column}>{column}</option>)}</select> : <input value={claimColumn} maxLength={63} onChange={(event) => setClaimColumn(event.target.value)} placeholder="Existing column name" />}</label>
        <button type="button" disabled={!claimName || !claimColumn} onClick={() => { onChange(rules.map((rule) => rule.scope.claim === claimName ? { ...rule, reviewed: false } : rule), { ...claims, [claimName]: claimColumn }); setClaimName(''); setClaimColumn(''); }}>Add identity attribute</button>
      </details>
      {detectedLabels.map((label) => <div className="query-entry" key={label}><h4>{label}</h4><label>Add readable resource<select value="" onChange={(event) => { const resource = resources[Number(event.target.value)]; if (event.target.value === '' || !resource) return; onChange([...rules, { label, schema: resource.schema, relation: resource.relation, fields: [], scope: { kind: 'pending' }, reviewed: false }], claims); }}><option value="">Select an existing table</option>{resources.filter((resource) => !(resource.schema === identity.schema && resource.relation === identity.relation)).map((resource) => <option key={JSON.stringify([resource.schema, resource.relation])} value={resources.indexOf(resource)} disabled={rules.some((rule) => rule.label === label && rule.schema === resource.schema && rule.relation === resource.relation)}>{resource.schema}.{resource.relation}</option>)}</select></label>
        {rules.map((rule, index) => { if (rule.label !== label) return null; const resource = resources.find((item) => item.schema === rule.schema && item.relation === rule.relation); const fields = resource?.scalarColumns || rule.fields;
          return <details className="query-entry" key={JSON.stringify([rule.schema, rule.relation])}><summary>{rule.schema}.{rule.relation} · {rule.fields.length} fields · {rule.scope.kind} · {rule.reviewed ? 'reviewed' : 'review needed'}</summary>
            <p>Readable scalar fields (up to 32). Include the fields needed for search, the unique key and display name. Structured JSON, credential fields and custom types are excluded.</p>
            {fields.map((column) => <label className="check" key={column}><input type="checkbox" checked={rule.fields.includes(column)} disabled={!rule.fields.includes(column) && rule.fields.length >= 32} onChange={(event) => update(index, { fields: event.target.checked ? [...rule.fields, column] : rule.fields.filter((name) => name !== column) })} />{column}</label>)}
            {!resource && <p>Load the resource's metadata page to edit its fields.</p>}
            <label>Row scope<select value={rule.scope.kind} onChange={(event) => update(index, { scope: { kind: event.target.value } })}><option value="pending">Select a verified rule</option><option value="all">All rows in this reviewed resource</option><option value="user">Matches the database user ID</option><option value="email">Matches the verified email</option><option value="claim">Matches a mapped user attribute</option><option value="membership">Matches existing team/group membership</option></select></label>
            {!['all', 'pending'].includes(rule.scope.kind) && <label>Resource scope column<select value={rule.scope.column || ''} onChange={(event) => update(index, { scope: { ...rule.scope, column: event.target.value } })}><option value="">Select column</option>{fields.map((column) => <option key={column} value={column}>{column}</option>)}</select></label>}
            {rule.scope.kind === 'claim' && <label>Matched user attribute<select value={rule.scope.claim || ''} onChange={(event) => update(index, { scope: { ...rule.scope, claim: event.target.value } })}><option value="">Select mapped attribute</option>{Object.keys(claims).map((name) => <option key={name}>{name}</option>)}</select></label>}
            {rule.scope.kind === 'membership' && <div><p>Map an existing membership relation. Its user ID must match the stable database user ID. The group ID must match the resource scope column.</p>{(['schema', 'relation', 'userColumn', 'groupColumn', 'activeColumn', 'tenantColumn'] as const).map((key) => <label key={key}>{({ schema: 'Membership schema', relation: 'Membership table', userColumn: 'Member user-ID column', groupColumn: 'Group-ID column', activeColumn: 'Active boolean column (optional)', tenantColumn: 'Microsoft tenant-ID column (optional)' })[key]}<input value={rule.scope.membership?.[key] || ''} maxLength={63} onChange={(event) => update(index, { scope: { ...rule.scope, membership: { schema: '', relation: '', userColumn: '', groupColumn: '', ...rule.scope.membership, [key]: event.target.value } } })} /></label>)}</div>}
            <label className="check"><input type="checkbox" checked={rule.reviewed} disabled={!rule.fields.length || rule.scope.kind === 'pending'} onChange={(event) => update(index, { reviewed: event.target.checked })} />I verified these fields and this row scope against the native application's read permissions</label>
            <button type="button" onClick={() => onChange(rules.filter((_, position) => position !== index), claims)}>Remove resource rule</button>
          </details>;
        })}
      </div>)}
      {!detectedLabels.length && <p>Detect the user mapping and its role values to configure resource permissions.</p>}
      <p>Use “Save and check my access” below to save this adapter in IQ Knowledge. Then verify your email and configure a business search profile. No execution-role translation or PostgreSQL changes are required in this mode.</p>
    </fieldset>
  </div>;
}
