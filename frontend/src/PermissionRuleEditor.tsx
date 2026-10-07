import { useEffect, useState } from 'react';
import { suggestPermissionDrafts } from './permission-suggestions.mjs';

type Resource = { schema: string; relation: string; columns: string[] };
type Rule = { schema: string; relation: string; fields: string[]; scope: 'pending' | 'all' | 'user'; userColumn?: string; reviewed: boolean };
type Draft = { label: string; executionRole: string; resources: Rule[] };
type Link = { sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] };
type Props = { identity: { schema: string; relation: string; userId: string }; relationships: Link[]; labels: string[]; resources: Resource[]; api: (path: string, init?: RequestInit) => Promise<Response> };
const sensitive = (name: string) => /password|secret|token|backupcode/.test(name.toLowerCase().replaceAll('_', ''));

export default function PermissionRuleEditor({ labels, resources: evidenceResources, relationships, identity, api }: Props) {
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
  const [preview, setPreview] = useState('');
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
    setDrafts((current) => current.map((draft) => draft.label === label ? transform(draft) : draft)); setPreview('');
  }
  function updateRule(label: string, index: number, transform: (rule: Rule) => Rule) {
    update(label, (draft) => ({ ...draft, resources: draft.resources.map((rule, position) => position === index ? transform(rule) : rule) }));
  }
  async function prepare() {
    setBusy(true); setMessage('Loading resources and preparing suggestions…'); setPreview('');
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
      const response = await api(`/api/admin/postgres/auth/permission-drafts${generate ? '/preview' : ''}`, { method: generate ? 'POST' : 'PUT', body: JSON.stringify(selectedDraft ? [selectedDraft] : drafts) });
      const result = await response.json();
      if (!response.ok) throw new Error(generate ? 'Preview requires reviewed rules, selected fields and row scope, new role names, and readable base tables without PUBLIC SELECT grants.' : 'Permission drafts could not be saved. Check role names and resource fields.');
      if (generate) { setPreview(result.sql); setMessage('SQL preview validated. Review it before applying it in your database. Afterwards detect the new execution roles and save their label translations.'); }
      else setMessage('Permission drafts saved. Drafts do not grant access or enable search.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Permission draft operation failed.'); }
    finally { setBusy(false); }
  }
  return <div className="query-entry"><h4>Permission rules by detected label</h4><fieldset disabled={busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
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
        return <details className="query-entry" key={`${rule.schema}.${rule.relation}`}><summary>{rule.schema}.{rule.relation} — {rule.fields.length} fields · {rule.reviewed ? 'reviewed' : rule.scope === 'pending' ? 'row scope needed' : 'review needed'}</summary>
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
    {message && <p role="status">{message}</p>}{preview && <><p>Applying this SQL changes database roles, grants, and row policies. It has not been executed by the app.</p><textarea aria-label="Permission deployment SQL preview" rows={16} readOnly value={preview} /></>}
  </fieldset></div>;
}
