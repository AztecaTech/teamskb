import { useEffect, useState } from 'react';

type Resource = { schema: string; relation: string; columns: string[] };
type Rule = { schema: string; relation: string; fields: string[]; scope: 'pending' | 'all' | 'user'; userColumn?: string; reviewed: boolean };
type Draft = { label: string; executionRole: string; resources: Rule[] };
type Props = { labels: string[]; resources: Resource[]; api: (path: string, init?: RequestInit) => Promise<Response> };
const sensitive = (name: string) => /password|secret|token|backupcode/.test(name.toLowerCase().replaceAll('_', ''));

export default function PermissionRuleEditor({ labels, resources, api }: Props) {
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
  async function save(generate = false) {
    setBusy(true); setMessage('');
    try {
      const response = await api(`/api/admin/postgres/auth/permission-drafts${generate ? '/preview' : ''}`, { method: generate ? 'POST' : 'PUT', body: JSON.stringify(drafts) });
      const result = await response.json();
      if (!response.ok) throw new Error(generate ? 'Preview requires reviewed rules, selected fields and row scope, new role names, and readable base tables without PUBLIC SELECT grants.' : 'Permission drafts could not be saved. Check role names and resource fields.');
      if (generate) { setPreview(result.sql); setMessage('SQL preview validated. Review it before applying it in your database. Afterwards detect the new execution roles and save their label translations.'); }
      else setMessage('Permission drafts saved. Drafts do not grant access or enable search.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Permission draft operation failed.'); }
    finally { setBusy(false); }
  }
  return <div className="query-entry"><h4>Permission rules by detected label</h4>
    <p className="muted">Each label gets its own draft. Select the resources and fields it may read, then review the row scope. No access is assumed from a label's name.</p>
    {drafts.map((draft) => <div className="query-entry" key={draft.label}><h4>{draft.label}</h4>
      <label>New restricted execution role<input value={draft.executionRole} maxLength={63} onChange={(event) => update(draft.label, (item) => ({ ...item, executionRole: event.target.value }))} /></label>
      <label>Add discovered resource<select value="" disabled={busy} onChange={(event) => {
        if (event.target.value === '') return;
        const resource = resources[Number(event.target.value)]; if (!resource) return;
        update(draft.label, (item) => ({ ...item, resources: [...item.resources, { schema: resource.schema, relation: resource.relation, fields: [], scope: 'pending', reviewed: false }] }));
      }}><option value="">Select resource</option>{resources.map((resource, index) => <option key={`${resource.schema}.${resource.relation}`} value={index} disabled={draft.resources.some((rule) => rule.schema === resource.schema && rule.relation === resource.relation)}>{resource.schema}.{resource.relation}</option>)}</select></label>
      {draft.resources.map((rule, index) => {
        const resource = resources.find((item) => item.schema === rule.schema && item.relation === rule.relation);
        return <div className="query-entry" key={`${rule.schema}.${rule.relation}`}><strong>{rule.schema}.{rule.relation}</strong>
          <p>Readable fields (up to 32 per resource)</p>{resource?.columns.filter((field) => !sensitive(field)).map((field) => <label className="check" key={field}><input type="checkbox" checked={rule.fields.includes(field)} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, reviewed: false, fields: event.target.checked ? [...item.fields, field] : item.fields.filter((name) => name !== field) }))} />{field}</label>)}
          {!resource && <p role="status">This resource is no longer in the discovery result. Rediscover and review it.</p>}
          <label>Row scope<select value={rule.scope} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, scope: event.target.value as Rule['scope'], reviewed: false }))}><option value="pending">Choose scope</option><option value="all">All rows in this selected resource</option><option value="user">Rows matching the verified database user ID</option></select></label>
          {rule.scope === 'user' && <label>User ID column<select value={rule.userColumn || ''} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, userColumn: event.target.value, reviewed: false }))}><option value="">Select a reviewed user-ID column</option>{rule.fields.map((field) => <option key={field} value={field}>{field}</option>)}</select></label>}
          <label className="check"><input type="checkbox" checked={rule.reviewed} onChange={(event) => updateRule(draft.label, index, (item) => ({ ...item, reviewed: event.target.checked }))} />I reviewed the selected fields and row scope for this label</label>
          <button type="button" onClick={() => update(draft.label, (item) => ({ ...item, resources: item.resources.filter((_, position) => position !== index) }))}>Remove resource</button>
        </div>;
      })}
      {draft.resources.length === 0 && <p>No read rules defined for this label.</p>}
    </div>)}
    <div className="button-row"><button type="button" disabled={busy || !loaded} onClick={() => void save()}>Save permission drafts</button><button type="button" disabled={busy || !loaded || drafts.length === 0} onClick={() => void save(true)}>Generate reviewed SQL preview</button></div>
    {message && <p role="status">{message}</p>}{preview && <><p>Applying this SQL changes database roles, grants, and row policies. It has not been executed by the app.</p><textarea aria-label="Permission deployment SQL preview" rows={16} readOnly value={preview} /></>}
  </div>;
}
