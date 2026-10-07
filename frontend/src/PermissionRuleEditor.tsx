import { useEffect, useRef, useState } from 'react';
import { suggestPermissionDrafts } from './permission-suggestions.mjs';

type Resource = { schema: string; relation: string; columns: string[] };
type Rule = { schema: string; relation: string; fields: string[]; scope: 'pending' | 'all' | 'user'; userColumn?: string; reviewed: boolean };
type Draft = { label: string; executionRole: string; resources: Rule[] };
type Link = { sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] };
type Preview = { sql: string; canApply?: boolean; adapterFingerprint?: string; previewToken?: string; previewExpiresAt?: number; drafts: Draft[] };
type Props = { identity: { schema: string; relation: string; userId: string }; relationships: Link[]; labels: string[]; resources: Resource[]; api: (path: string, init?: RequestInit) => Promise<Response>; onBeforePreview: () => Promise<void>; onApplied: () => Promise<void> };
const sensitive = (name: string) => /password|secret|token|backupcode/.test(name.toLowerCase().replaceAll('_', ''));

export default function PermissionRuleEditor({ labels, resources: evidenceResources, relationships, identity, api, onBeforePreview, onApplied }: Props) {
  const [catalog, setCatalog] = useState<Resource[]>([]);
  const [resourceCursor, setResourceCursor] = useState<{ schema: string; name: string } | null>(null);
  const [resourceMessage, setResourceMessage] = useState('');
  const [resourceBusy, setResourceBusy] = useState(false);
  const resources = [...new Map([...evidenceResources, ...catalog].map((resource) => [JSON.stringify([resource.schema, resource.relation]), resource])).values()];
  async function loadResources(append = false) {
    setResourceBusy(true);
    try {
      const cursor = append && resourceCursor ? `?afterSchema=${encodeURIComponent(resourceCursor.schema)}&afterName=${encodeURIComponent(resourceCursor.name)}` : '';
      const response = await api(`/api/admin/postgres/auth/resources${cursor}`);
      const page = await response.json() as { resources: Resource[]; nextSchema?: string; nextName?: string; columnsTruncated?: boolean; error?: string };
      if (!response.ok) throw new Error(`Resource metadata discovery failed (${page.error || 'unknown'}).`);
      setCatalog((current) => append ? [...current, ...page.resources] : page.resources);
      setResourceCursor(page.nextSchema ? { schema: page.nextSchema, name: page.nextName || '' } : null);
      setResourceMessage(`${page.resources.length} readable resources loaded on this page. No table rows were read.${page.columnsTruncated ? ' Some column lists were limited to 100 fields.' : ''}`);
    } catch (error) { setResourceMessage(error instanceof Error ? error.message : 'Resource discovery failed.'); }
    finally { setResourceBusy(false); }
  }
  useEffect(() => { void loadResources(); }, []);
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [message, setMessage] = useState('');
  const [preview, setPreview] = useState<Preview | null>(null);
  const [impactConfirmed, setImpactConfirmed] = useState(false);
  const [appliedNext, setAppliedNext] = useState('');
  const feedback = useRef<HTMLDivElement>(null);
  function showResult() { requestAnimationFrame(() => feedback.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })); }
  useEffect(() => { setPreview(null); setImpactConfirmed(false); }, [JSON.stringify(identity)]);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const response = await api('/api/admin/postgres/auth/permission-drafts');
        if (!response.ok) throw new Error('Saved permission drafts could not be loaded.');
        const saved = await response.json() as Draft[];
        const next: Draft[] = [];
        for (const label of labels) {
          const existing = saved.find((item) => item.label === label);
          const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label));
          const suffix = [...new Uint8Array(hash)].slice(0, 8).map((value) => value.toString(16).padStart(2, '0')).join('');
          next.push(existing || { label, executionRole: `iqkb_mapped_${suffix}`, resources: [] });
        }
        if (active) { setDrafts(next); setLoaded(true); }
      } catch (error) { if (active) setMessage(error instanceof Error ? error.message : 'Draft loading failed.'); }
    })();
    return () => { active = false; };
  }, [JSON.stringify(labels)]);

  function update(label: string, transform: (draft: Draft) => Draft) {
    setDrafts((current) => current.map((draft) => draft.label === label ? transform(draft) : draft)); setPreview(null); setImpactConfirmed(false);
  }
  function updateRule(label: string, index: number, transform: (rule: Rule) => Rule) {
    update(label, (draft) => ({ ...draft, resources: draft.resources.map((rule, position) => position === index ? transform(rule) : rule) }));
  }
  async function prepare() {
    setBusy(true); setMessage('Loading resources and preparing suggestions…'); setPreview(null); setImpactConfirmed(false);
    try {
      let cursor = ''; const found: Resource[] = []; let more: { schema: string; name: string } | null = null;
      for (let pageNumber = 0; pageNumber < 4; pageNumber++) {
        const response = await api(`/api/admin/postgres/auth/resources${cursor}`);
        const page = await response.json() as { resources: Resource[]; nextSchema?: string; nextName?: string; error?: string };
        if (!response.ok) throw new Error(`Resource discovery failed (${page.error || 'unknown'}).`);
        found.push(...page.resources);
        more = page.nextSchema ? { schema: page.nextSchema, name: page.nextName || '' } : null;
        if (!more) break;
        cursor = `?afterSchema=${encodeURIComponent(more.schema)}&afterName=${encodeURIComponent(more.name)}`;
      }
      setCatalog(found); setResourceCursor(more);
      const prepared = suggestPermissionDrafts(drafts, found, relationships, identity);
      setDrafts(prepared);
      const saveResponse = await api('/api/admin/postgres/auth/permission-drafts', { method: 'PUT', body: JSON.stringify(prepared) });
      if (!saveResponse.ok) throw new Error('Suggestions were prepared but could not be saved.');
      setMessage(`Prepared and saved ${prepared.reduce((count, draft) => count + draft.resources.length, 0)} resource rules for ${prepared.length} labels. Existing edits were preserved. Fields are suggested; user links are proposed row scopes, not permission proof. Review unresolved scopes before generating SQL.${more ? ' More resources remain available.' : ''}`);
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Automatic preparation failed.'); }
    finally { setBusy(false); }
  }
  async function save(generate = false, selectedDraft?: Draft) {
    setBusy(true); setMessage('');
    try {
      if (generate) { setPreview(null); setImpactConfirmed(false); await onBeforePreview(); }
      const selected = selectedDraft ? [selectedDraft] : drafts;
      const response = await api(`/api/admin/postgres/auth/permission-drafts${generate ? '/preview' : ''}`, { method: generate ? 'POST' : 'PUT', body: JSON.stringify(selected) });
      const result = await response.json();
      if (!response.ok) throw new Error(generate ? `Preview failed (${result.error || 'unknown'}). Check reviewed scopes, fields, new role names, and table privileges.` : 'Permission drafts could not be saved. Check role names and resource fields.');
      if (generate) { setPreview({ ...result, drafts: selected }); setMessage('Preview ready. Review the SQL and its effect on your application, then apply the reviewed mapping below.'); }
      else setMessage('Drafts saved. Next, generate a reviewed SQL preview and apply the mapping to create its execution roles.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Permission draft operation failed.'); }
    finally { setBusy(false); showResult(); }
  }
  async function apply() {
    if (!preview || !impactConfirmed) return;
    setBusy(true); setMessage('Applying reviewed rules and connecting their labels…');
    try {
      const response = await api('/api/admin/postgres/auth/permission-drafts/apply', { method: 'POST', body: JSON.stringify({ drafts: preview.drafts, adapterFingerprint: preview.adapterFingerprint, previewToken: preview.previewToken, previewExpiresAt: preview.previewExpiresAt, acknowledgeImpact: impactConfirmed }) });
      const result = await response.json() as { error?: string; deployed?: boolean; accessStatus?: string; userId?: string; databaseRole?: string; accessError?: string };
      if (!response.ok) {
        if (result.error === 'database_deployment_outcome_unknown') { setPreview(null); throw new Error('The database deployment result could not be confirmed. Detect execution roles before retrying. If the new roles are installed, save their label translations.'); }
        if (result.deployed) { setPreview(null); throw new Error('Database rules were installed, but the adapter could not be saved. Detect the installed execution roles and save their label translations.'); }
        const advice: Record<string, string> = { database_setup_privileges_required: 'The URI login needs permission to create roles and alter the selected tables. Apply the SQL through your database administrator, then detect roles.', database_setup_busy: 'A selected table is busy or setup timed out. Retry when it is idle.', permission_preview_changed_or_expired: 'Generate a fresh preview and review it again.', execution_role_already_exists: 'Detect the installed roles and save their label translations; existing roles are never overwritten.', authorization_mapping_changed_regenerate_preview: 'The authorization mapping changed. Generate a fresh preview.' };
        throw new Error(`Mapping was not applied (${result.error || 'unknown'}). ${advice[result.error || ''] || 'Review the rules and database privileges, then regenerate the preview.'}`);
      }
      setPreview(null); setImpactConfirmed(false);
      setAppliedNext(result.accessStatus === 'connected' ? 'postgres-query-catalog' : result.accessStatus === 'database_permission_mapping_required' ? 'postgres-authorization' : 'database-access');
      setMessage(result.accessStatus === 'connected' ? `Mapping applied. Connected as database user ${result.userId}, role ${result.databaseRole}. Configure a searchable query next.` : `Mapping applied and label translations saved. ${result.accessStatus === 'database_permission_mapping_required' ? `Your label still needs permission rules (${result.accessError || 'unmapped label'}).` : 'Verify your database email to connect your account.'}`);
      try { await onApplied(); } catch { setMessage((current) => `${current} Refresh database access to update the displayed status.`); }
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Mapping application failed.'); }
    finally { setBusy(false); showResult(); }
  }
  return <div id="postgres-permission-drafts" className="query-entry"><h4>Permission rules by detected label</h4><fieldset disabled={busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
    <p className="muted">Each label gets its own draft. Select the resources and fields it may read, then review the row scope. No access is assumed from a label's name.</p>
    <button type="button" disabled={busy || !loaded || resourceBusy} onClick={() => void prepare()}>Prepare mapping drafts automatically</button>
    {resourceMessage && <p role="status">{resourceMessage}</p>}<div className="button-row"><button type="button" disabled={resourceBusy} onClick={() => void loadResources()}>Refresh resource catalog</button>{resourceCursor && <button type="button" disabled={resourceBusy} onClick={() => void loadResources(true)}>Load more resources</button>}</div>
    {drafts.map((draft) => <div className="query-entry" key={draft.label}><h4>{draft.label}</h4>
      <div className="button-row"><button type="button" onClick={() => update(draft.label, (item) => ({ ...item, resources: item.resources.map((rule) => ({ ...rule, scope: 'all', reviewed: false })) }))}>Set all selected resources to all rows</button><button type="button" onClick={() => update(draft.label, (item) => ({ ...item, resources: item.resources.map((rule) => ({ ...rule, reviewed: rule.fields.length > 0 && (rule.scope === 'all' || (rule.scope === 'user' && !!rule.userColumn && rule.fields.includes(rule.userColumn))) })) }))}>Mark complete rules reviewed</button></div>
      <p className="muted">All-rows scope must reflect the permissions you intend to grant. It is never selected from the label automatically.</p>
      <label>New restricted execution role<input value={draft.executionRole} maxLength={63} onChange={(event) => update(draft.label, (item) => ({ ...item, executionRole: event.target.value }))} /></label>
      <label>Add discovered resource<select value="" disabled={busy} onChange={(event) => {
        if (event.target.value === '') return;
        const resource = resources[Number(event.target.value)]; if (!resource) return;
        update(draft.label, (item) => ({ ...item, resources: [...item.resources, { schema: resource.schema, relation: resource.relation, fields: [], scope: 'pending', reviewed: false }] }));
      }}><option value="">Select resource</option>{resources.map((resource, index) => <option key={`${resource.schema}.${resource.relation}`} value={index} disabled={draft.resources.some((rule) => rule.schema === resource.schema && rule.relation === resource.relation)}>{resource.schema}.{resource.relation}</option>)}</select></label>
      {draft.resources.map((rule, index) => {
        const resource = resources.find((item) => item.schema === rule.schema && item.relation === rule.relation);
        return <details className="query-entry" key={`${rule.schema}.${rule.relation}`}><summary>{rule.schema}.{rule.relation} — {rule.fields.length} fields · {rule.scope === 'all' ? 'all rows' : rule.scope === 'user' ? `matched user via ${rule.userColumn || 'column needed'}` : 'row scope needed'} · {rule.reviewed ? 'reviewed' : 'review needed'}</summary>
          <p>Readable fields (up to 32 per resource)</p>{resource?.columns.filter((field) => !sensitive(field)).map((field) => <label className="check" key={field}><input type="checkbox" checked={rule.fields.includes(field)} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, reviewed: false, fields: event.target.checked ? [...item.fields, field] : item.fields.filter((name) => name !== field) }))} />{field}</label>)}
          {!resource && <p role="status">This resource is no longer in the discovery result. Rediscover and review it.</p>}
          <label>Row scope<select value={rule.scope} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, scope: event.target.value as Rule['scope'], reviewed: false }))}><option value="pending">Choose scope</option><option value="all">All rows in this selected resource</option><option value="user">Rows matching the verified database user ID</option></select></label>
          {rule.scope === 'user' && <label>User ID column<select value={rule.userColumn || ''} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, userColumn: event.target.value, reviewed: false }))}><option value="">Select a reviewed user-ID column</option>{rule.fields.map((field) => <option key={field} value={field}>{field}</option>)}</select></label>}
          <label className="check"><input type="checkbox" checked={rule.reviewed} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, reviewed: event.target.checked }))} />I reviewed the selected fields and row scope for this label</label>
          <button type="button" onClick={() => update(draft.label, (item) => ({ ...item, resources: item.resources.filter((_, position) => position !== index) }))}>Remove resource</button>
        </details>;
      })}
      {draft.resources.length === 0 && <p>No read rules defined for this label.</p>}
      <button type="button" disabled={busy || draft.resources.length === 0} onClick={() => void save(true, draft)}>Generate SQL preview for this label</button>
    </div>)}
    <div className="button-row"><button type="button" disabled={busy || !loaded} onClick={() => void save()}>Save permission drafts</button><button type="button" disabled={busy || !loaded || drafts.length === 0} onClick={() => void save(true)}>Generate reviewed SQL preview</button></div>
    <div ref={feedback} aria-live="polite">{message && <p role="status">{message}</p>}{appliedNext && <p><a href={`#${appliedNext}`}>{appliedNext === 'postgres-query-catalog' ? 'Configure searchable queries' : appliedNext === 'database-access' ? 'Verify database email' : 'Complete your label mapping'}</a></p>}{preview && <><p>Applying this SQL creates restricted roles, grants the selected fields, and enables row security on the selected tables. Enabling row security can affect your native application's database access. The SQL has not run.</p><textarea aria-label="Permission deployment SQL preview" rows={16} readOnly value={preview.sql} />{preview.canApply ? <><label className="check"><input type="checkbox" checked={impactConfirmed} onChange={(event) => setImpactConfirmed(event.target.checked)} />I reviewed this SQL, the selected access rules, and the effect on my native application.</label><button type="button" disabled={busy || !impactConfirmed} onClick={() => void apply()}>{busy ? 'Applying mapping…' : 'Apply reviewed mapping and check my access'}</button></> : <p>Save the authorization mapping, then generate a new preview to apply it here. You can also apply this SQL through your database administrator.</p>}</>}</div>
  </fieldset></div>;
}
