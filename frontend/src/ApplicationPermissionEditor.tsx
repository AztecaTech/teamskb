import { useEffect, useRef, useState } from 'react';
import { permissionRuleIssues } from './postgres-setup.mjs';

export type Membership = { schema: string; relation: string; userColumn: string; groupColumn: string; activeColumn?: string; tenantColumn?: string };
export type ReadRule = { label: string; schema: string; relation: string; fields: string[]; scope: { kind: string; column?: string; claim?: string; membership?: Membership }; reviewed: boolean };
type Resource = { schema: string; relation: string; columns: string[]; scalarColumns?: string[] };
type Props = { labels: string[]; currentLabel?: string; rules: ReadRule[]; claims: Record<string, string>; identity: { schema: string; relation: string }; disabled: boolean; onChange: (rules: ReadRule[], claims: Record<string, string>) => void; onResourceSelected: (schema: string, relation: string) => void; api: (path: string, init?: RequestInit) => Promise<Response> };

export default function ApplicationPermissionEditor({ labels, currentLabel, rules, claims, identity, disabled, onChange, onResourceSelected, api }: Props) {
  const [resources, setResources] = useState<Resource[]>([]);
  const [cursor, setCursor] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [claimName, setClaimName] = useState('');
  const [claimColumn, setClaimColumn] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [editingResource, setEditingResource] = useState('');
  const [automatic, setAutomatic] = useState<{configured:boolean;status?:string;userId?:string;label?:string;rules?:ReadRule[];claimColumns?:Record<string,string>;error?:string} | null>(null);
  const loadGeneration = useRef(0);
  async function detectPermissions(generation: number) {
    const response=await api('/api/admin/postgres/auth/permissions');
    const result=await response.json() as NonNullable<typeof automatic>;
    if (generation !== loadGeneration.current) return true;
    setAutomatic(result);
    if (!response.ok) { setMessage(`Automatic permission lookup could not complete (${result.error || 'unknown'}). The native permission source must resolve this account; manual selections cannot override it.`);return true; }
    if (result.configured && result.rules?.length) {
      onChange(result.rules,result.claimColumns || {});
      if (result.rules.length===1) onResourceSelected(result.rules[0].schema,result.rules[0].relation);
      setMessage(`Allowed fields and row access selected automatically for database user ${result.userId}, label ${result.label}. Save permissions and continue.`);
    } else setMessage('Automatic selection needs the existing application’s permission source. Table metadata and the shared connection’s access do not define a user’s rights. Your deployment operator can connect the native permission endpoint once; manual configuration remains available below.');
    return result.configured;
  }
  async function load(append = false) {
    const generation = ++loadGeneration.current;
    setBusy(true);
    try {
      // An authoritative source already supplies the allowed resources. Do not
      // require scanning the shared service account's metadata before using it.
      if (!append && await detectPermissions(generation)) return;
      let next = append ? cursor : '';
      for (let number = 0; number < 4; number++) {
        const response = await api(`/api/admin/postgres/auth/resources${next}`);
        const page = await response.json() as { resources: Resource[]; nextSchema?: string; nextName?: string; error?: string };
        if (generation !== loadGeneration.current) return;
        if (!response.ok) throw new Error(`Resource discovery failed (${page.error || 'unknown'}).`);
        const replace = !append && number === 0;
        setResources((current) => replace ? page.resources : [...current.filter((item) => !page.resources.some((resource) => resource.schema === item.schema && resource.relation === item.relation)), ...page.resources]);
        const previous = next;
        next = page.nextSchema ? `?afterSchema=${encodeURIComponent(page.nextSchema)}&afterName=${encodeURIComponent(page.nextName || '')}` : '';
        setCursor(next);
        if (!next || next === previous) break;
      }
    } catch (error) { if (generation === loadGeneration.current) setMessage(error instanceof Error ? error.message : 'Permission discovery failed.'); }
    finally { if (generation === loadGeneration.current) setBusy(false); }
  }
  useEffect(() => { setAutomatic(null); void load(); return () => { loadGeneration.current++; }; }, [identity.schema,identity.relation,currentLabel]);
  function update(index: number, change: Partial<ReadRule>) { onChange(rules.map((rule, position) => position === index ? { ...rule, ...change, reviewed: change.reviewed ?? false } : rule), claims); }
  const identityResource = resources.find((resource) => resource.schema === identity.schema && resource.relation === identity.relation);
  const detectedLabels = [...new Set([...(currentLabel ? [currentLabel] : []), ...labels, ...rules.map((rule) => rule.label)])];
  const currentRules = rules.filter((rule) => rule.label === currentLabel);
  const automated=automatic?.configured===true;
  if (automated) return <div id="application-permissions" className="query-entry"><h4>Automatically selected permissions</h4><p role="status">{message}</p><p>Fields and row access come from your native permission source. The server rechecks its decisions for every database operation.</p><button type="button" disabled={disabled || busy} onClick={()=>void load()}>Refresh my permissions</button>{automatic.rules?.map((rule)=><div className="query-entry" key={JSON.stringify([rule.schema,rule.relation])}><strong>{rule.schema}.{rule.relation}</strong><p>Permitted fields: {rule.fields.join(', ')}.</p><p>Row access: {rule.scope.kind}{rule.scope.column ? ` on ${rule.scope.column}` : ''}.</p><button type="button" disabled={disabled || busy} onClick={()=>{onResourceSelected(rule.schema,rule.relation);setMessage(`Selected ${rule.schema}.${rule.relation} for the first search profile. Save permissions and continue.`);}}>Search this resource</button></div>)}</div>;
  return <div id="application-permissions" className="query-entry"><h4>Application permission adapter</h4>
    {currentLabel && <p role="status">Your matched database label is <strong>{currentLabel}</strong>. {currentRules.some((rule) => rule.reviewed) ? 'A reviewed resource rule is configured. Save permissions to continue to search setup.' : currentRules.length ? 'Finish the fields and row access for your resource, then mark the rule reviewed.' : 'No resource is configured for this label yet. Choose a table under this label to begin.'}</p>}
    <p>Connect the native permission source once to have permitted fields and row access selected automatically for each matched user.</p>
    <p className="muted">Metadata supplies the table and field names. The native application's permission rules determine access. JSON visibility and custom backend rules still require an adapter extension.</p>
    <fieldset disabled={disabled || busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <div className="button-row"><button type="button" onClick={() => void load()}>Detect my permissions</button>{cursor && <button type="button" onClick={() => void load(true)}>Load more resources</button>}</div>
      {message && <p role="status">{message}</p>}
      <label>Find a resource<input type="search" value={resourceFilter} onChange={(event) => setResourceFilter(event.target.value)} placeholder="Filter loaded tables by schema or name" /></label>
      <p className="muted">{resources.length} resources loaded{cursor ? '; load more if your table is missing' : ''}.</p>
      <details><summary>Additional identity attributes (optional)</summary><p>For rules based on a native user name or organization ID, map an attribute to an existing column in the user relation. Values are read from the matched user, never entered by the search user.</p>
        {Object.entries(claims).map(([name, column]) => <p key={name}>{name} → {column} <button type="button" onClick={() => { const next = { ...claims }; delete next[name]; onChange(rules.map((rule) => rule.scope.claim === name ? { ...rule, reviewed: false } : rule), next); }}>Remove attribute</button></p>)}
        <label>Attribute name<input value={claimName} maxLength={63} onChange={(event) => setClaimName(event.target.value)} placeholder="Choose an attribute name" /></label>
        <label>Existing user column{identityResource ? <select value={claimColumn} onChange={(event) => setClaimColumn(event.target.value)}><option value="">Select column</option>{identityResource.scalarColumns?.map((column) => <option key={column} value={column}>{column}</option>)}</select> : <input value={claimColumn} maxLength={63} onChange={(event) => setClaimColumn(event.target.value)} placeholder="Existing column name" />}</label>
        <button type="button" disabled={!claimName || !claimColumn} onClick={() => { onChange(rules.map((rule) => rule.scope.claim === claimName ? { ...rule, reviewed: false } : rule), { ...claims, [claimName]: claimColumn }); setClaimName(''); setClaimColumn(''); }}>Add identity attribute</button>
      </details>
      {detectedLabels.map((label) => <div className="query-entry" key={label}><h4>{label}{label === currentLabel ? ' · Your database label' : ''}</h4><label>Add readable resource<select value="" onChange={(event) => { const resource = resources[Number(event.target.value)]; if (event.target.value === '' || !resource) return; onChange([...rules, { label, schema: resource.schema, relation: resource.relation, fields: [], scope: { kind: 'pending' }, reviewed: false }], claims); setEditingResource(JSON.stringify([label, resource.schema, resource.relation])); if (label === currentLabel) onResourceSelected(resource.schema, resource.relation); }}><option value="">Choose your first table</option>{resources.filter((resource) => !(resource.schema === identity.schema && resource.relation === identity.relation) && `${resource.schema}.${resource.relation}`.toLowerCase().includes(resourceFilter.toLowerCase())).map((resource) => <option key={JSON.stringify([resource.schema, resource.relation])} value={resources.indexOf(resource)} disabled={rules.some((rule) => rule.label === label && rule.schema === resource.schema && rule.relation === resource.relation)}>{resource.schema}.{resource.relation}</option>)}</select></label>
        {rules.map((rule, index) => { if (rule.label !== label) return null; const resource = resources.find((item) => item.schema === rule.schema && item.relation === rule.relation); const fields = resource?.scalarColumns || rule.fields;
          const issues = permissionRuleIssues(rule, claims);
          return <details className="query-entry" key={JSON.stringify([rule.schema, rule.relation])} open={editingResource === JSON.stringify([label, rule.schema, rule.relation]) || !rule.reviewed || undefined}><summary>{rule.schema}.{rule.relation} · {rule.fields.length} fields · {rule.scope.kind} · {rule.reviewed ? 'reviewed' : 'review needed'}</summary>
            <p>Readable scalar fields (up to 32). Include the fields needed for search, the unique key and display name. Structured JSON, credential fields and custom types are excluded.</p>
            {fields.map((column) => <label className="check" key={column}><input type="checkbox" checked={rule.fields.includes(column)} disabled={!rule.fields.includes(column) && rule.fields.length >= 32} onChange={(event) => update(index, { fields: event.target.checked ? [...rule.fields, column] : rule.fields.filter((name) => name !== column) })} />{column}</label>)}
            {!resource && <p>Load the resource's metadata page to edit its fields.</p>}
            <label>Row scope<select value={rule.scope.kind} onChange={(event) => update(index, { scope: { kind: event.target.value } })}><option value="pending">Select a verified rule</option><option value="all">All rows in this reviewed resource</option><option value="user">Matches the database user ID</option><option value="email">Matches the verified email</option><option value="claim">Matches a mapped user attribute</option><option value="membership">Matches existing team/group membership</option></select></label>
            {!['all', 'pending'].includes(rule.scope.kind) && <label>Resource scope column<select value={rule.scope.column || ''} onChange={(event) => update(index, { scope: { ...rule.scope, column: event.target.value } })}><option value="">Select column</option>{fields.map((column) => <option key={column} value={column}>{column}</option>)}</select></label>}
            {rule.scope.kind === 'claim' && <label>Matched user attribute<select value={rule.scope.claim || ''} onChange={(event) => update(index, { scope: { ...rule.scope, claim: event.target.value } })}><option value="">Select mapped attribute</option>{Object.keys(claims).map((name) => <option key={name}>{name}</option>)}</select></label>}
            {rule.scope.kind === 'membership' && <div><p>Map an existing membership relation. Its user ID must match the stable database user ID. The group ID must match the resource scope column.</p>{(['schema', 'relation', 'userColumn', 'groupColumn', 'activeColumn', 'tenantColumn'] as const).map((key) => <label key={key}>{({ schema: 'Membership schema', relation: 'Membership table', userColumn: 'Member user-ID column', groupColumn: 'Group-ID column', activeColumn: 'Active boolean column (optional)', tenantColumn: 'Microsoft tenant-ID column (optional)' })[key]}<input value={rule.scope.membership?.[key] || ''} maxLength={63} onChange={(event) => update(index, { scope: { ...rule.scope, membership: { schema: '', relation: '', userColumn: '', groupColumn: '', ...rule.scope.membership, [key]: event.target.value } } })} /></label>)}</div>}
            {issues.length > 0 && <div role="status"><strong>To complete this resource:</strong><ul>{issues.map((issue) => <li key={issue}>{issue}</li>)}</ul></div>}
            <label className="check"><input type="checkbox" checked={rule.reviewed} disabled={issues.length > 0} onChange={(event) => update(index, { reviewed: event.target.checked })} />These fields and this row access match the native application's existing permissions</label>
            {rule.reviewed && label === currentLabel && <button type="button" onClick={() => { onResourceSelected(rule.schema, rule.relation); setMessage(`Selected ${rule.schema}.${rule.relation} for the search profile. Save permissions and continue below.`); }}>Use this resource for the first search profile</button>}
            <button type="button" onClick={() => onChange(rules.filter((_, position) => position !== index), claims)}>Remove resource rule</button>
          </details>;
        })}
      </div>)}
      {!detectedLabels.length && <p>Detect the user mapping and its role values to configure resource permissions.</p>}
      <p>Use “Save permissions and continue” below. The app checks your account and opens searchable metadata. Other labels remain unavailable until their own rules are configured.</p>
    </fieldset>
  </div>;
}
