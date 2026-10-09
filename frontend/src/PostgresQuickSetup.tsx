import { useEffect, useRef, useState } from 'react';
import { candidateColumnMapping } from './mapping-prefill.mjs';
import { resourceKey } from './permissions/types';
import type { PermissionApi, PermissionResource, PermissionResourcePage, PostgresAuthAdapter } from './permissions/types';

type Candidate = { schema: string; relation: string; ready: boolean; columns?: { name: string; dataType: string }[] };
type Selection = { schema: string; relation: string; roles: string[] };
type Props = {
  active: boolean;
  adapter: PostgresAuthAdapter;
  email: string;
  disabled: boolean;
  api: PermissionApi;
  onConnected: (adapter: PostgresAuthAdapter) => Promise<void>;
};

export function supportsSimpleRoles(adapter: PostgresAuthAdapter) {
  return adapter.roleLabelAccess || (adapter.mode === 'application_rules' && adapter.permissionSource !== 'external' && !adapter.rules?.some((rule) => rule.reviewed));
}

const setupErrors: Record<string, string> = {
  database_email_mismatch: 'Use the same email as your verified Microsoft account.',
  user_email_not_found: 'That email has no account in the selected users table.',
  user_email_ambiguous: 'More than one database account has this email. Select the correct users table under Advanced.',
  user_inactive: 'Your database account is disabled.',
  include_your_role_for_access_check: 'Include your role on each selected table so the app can test your access.',
  advanced_permissions_preserved: 'An existing permission policy is configured. Manage it under Advanced; it has been preserved.',
  setup_changed_retry: 'Settings changed while access was being checked. Refresh and try again.',
  table_access_check_failed: 'The selected table could not pass its read-only access check. Your previous settings were preserved.',
  table_search_unsupported: 'This table needs a supported unique key and a readable text field. Use another table or configure it under Advanced.',
  application_labels_limit_exceeded: 'More than 100 roles were found. Use Advanced to configure this permission system.',
};

export default function PostgresQuickSetup({ active, adapter, email: verifiedEmail, disabled, api, onConnected }: Props) {
  const [mapping, setMapping] = useState(adapter);
  const [manualMapping, setManualMapping] = useState<PostgresAuthAdapter | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [resources, setResources] = useState<PermissionResource[]>([]);
  const [roles, setRoles] = useState<string[]>([]);
  const [currentRole, setCurrentRole] = useState('');
  const [selected, setSelected] = useState<Selection[]>([]);
  const [email, setEmail] = useState(verifiedEmail);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  const simple = supportsSimpleRoles(adapter);

  useEffect(() => { setEmail(verifiedEmail); }, [verifiedEmail]);
  useEffect(() => { setManualMapping(null); }, [adapter]);

  useEffect(() => {
    if (!active || !simple) return;
    const request = ++generation.current;
    let disposed = false;
    const current = () => !disposed && generation.current === request;
    async function load() {
      setBusy(true); setMessage('Detecting your database account, roles and searchable tables…');
      setRoles([]); setCurrentRole(''); setResources([]); setSelected([]); setCandidates([]);
      try {
        let chosen = manualMapping || adapter;
        if (!chosen.schema || !chosen.relation) {
          const found: Candidate[] = [];
          let after = '';
          for (let pages = 0; pages < 40; pages++) {
            const response = await api(`/api/admin/postgres/auth/discovery${after}`);
            if (!response.ok) throw new Error('The database connection could not read user metadata. Check the connection under Advanced.');
            const page = await response.json() as { candidates: Candidate[]; nextSchema?: string; nextName?: string };
            found.push(...page.candidates.filter((candidate) => candidate.ready || candidateColumnMapping(candidate)));
            if (!current()) return;
            if (!page.nextSchema) break;
            if (pages === 39) throw new Error('User discovery reached its limit. Choose the users table under Advanced.');
            after = `?afterSchema=${encodeURIComponent(page.nextSchema)}&afterName=${encodeURIComponent(page.nextName || '')}`;
          }
          if (!found.length) throw new Error('No users table could be recognized automatically. Choose its email and role columns under Advanced.');
          if (found.length !== 1) {
            setCandidates(found); setMessage('More than one users table was found. Choose the table containing your database account.'); return;
          }
          chosen = { ...adapter, schema: found[0].schema, relation: found[0].relation, columns: found[0].ready ? undefined : candidateColumnMapping(found[0]) || undefined };
        }
        setMapping(chosen);
        const response = await api('/api/admin/postgres/auth/labels', { method: 'POST', body: JSON.stringify(chosen) });
        const labels = await response.json() as { roles: string[]; currentRole: string; error?: string };
        if (!current()) return;
        if (!response.ok) throw new Error(setupErrors[labels.error || ''] || `Your database account could not be matched (${labels.error || 'connection unavailable'}). Check the users table under Advanced.`);
        const tables: PermissionResource[] = [];
        let after = '';
        for (let pages = 0; pages < 40; pages++) {
          const response = await api(`/api/admin/postgres/auth/resources${after}`);
          if (!response.ok) throw new Error('Searchable tables could not be detected. Your existing settings are preserved.');
          const page = await response.json() as PermissionResourcePage;
          tables.push(...page.resources.filter((table) => table.searchProfile && resourceKey(table) !== resourceKey(chosen)));
          if (!current()) return;
          if (!page.nextSchema) break;
          if (pages === 39) throw new Error('Table discovery reached its limit. Use Advanced to configure this database.');
          after = `?afterSchema=${encodeURIComponent(page.nextSchema)}&afterName=${encodeURIComponent(page.nextName || '')}`;
        }
        if (!current()) return;
        setRoles(labels.roles); setCurrentRole(labels.currentRole); setResources(tables);
        if (adapter.roleLabelAccess) {
          setSelected(tables.map((table) => ({ ...table, roles: (adapter.rules || []).filter((rule) => rule.reviewed && resourceKey(rule) === resourceKey(table)).map((rule) => rule.label).filter((role) => labels.roles.includes(role)) })).filter((table) => table.roles.length).map(({schema,relation,roles}) => ({schema,relation,roles})));
        }
        setMessage(tables.length ? '' : 'No searchable tables were found. Automatic search needs an existing unique key and a readable text field; inspect other resources under Advanced.');
      } catch (error) { if (current()) setMessage(error instanceof Error ? error.message : 'Database discovery failed.'); }
      finally { if (current()) setBusy(false); }
    }
    void load();
    return () => { disposed = true; };
  }, [active, simple, adapter, manualMapping, revision]); // Reload only on committed configuration or an explicit refresh.

  function chooseMapping(candidate: Candidate) {
    // The explicit candidate is kept locally; no mapping is saved during discovery.
    setManualMapping({ ...adapter, schema: candidate.schema, relation: candidate.relation, columns: candidate.ready ? undefined : candidateColumnMapping(candidate) || undefined });
  }

  function toggleTable(table: PermissionResource, enabled: boolean) {
    setSelected((previous) => enabled ? [...previous, {schema:table.schema,relation:table.relation,roles:[currentRole]}] : previous.filter((item) => resourceKey(item) !== resourceKey(table)));
  }
  function toggleRole(table: PermissionResource, role: string, enabled: boolean) {
    setSelected((previous) => previous.map((item) => resourceKey(item) === resourceKey(table) ? {...item,roles:enabled ? [...item.roles,role] : item.roles.filter((value) => value !== role)} : item));
  }

  async function connect(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage('Checking selected tables and preparing database search…');
    try {
      const response = await api('/api/admin/postgres/auth/quick-setup', { method: 'POST', body: JSON.stringify({mapping,email,resources:selected}) });
      const result = await response.json() as { adapter: PostgresAuthAdapter; tables: number; error?: string; table?: string };
      if (!response.ok) throw new Error((setupErrors[result.error || ''] || `Database setup could not finish (${result.error || 'unavailable'}). Your previous settings were preserved.`) + (result.table ? ` Table: ${result.table}.` : ''));
      await onConnected(result.adapter);
      setMessage(`Connected. ${result.tables} ${result.tables === 1 ? 'table is' : 'tables are'} ready for database search.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Database setup failed.'); }
    finally { setBusy(false); }
  }

  if (!simple) return <p>Existing permissions are configured. Open Advanced database settings to manage them.</p>;
  const validSelection = selected.length > 0 && selected.length <= 20 && selected.every((table) => table.roles.includes(currentRole));
  return <div id="postgres-quick-setup">
    <h3>Database search</h3>
    <p>Uses your database role labels. Choose searchable tables and their allowed roles.</p>
    {currentRole && <p>Your database role: <strong>{currentRole}</strong>.</p>}
    {candidates.length > 0 && <label>Users table<select value="" disabled={busy || disabled} onChange={(event) => { const candidate = candidates.find((item) => resourceKey(item) === event.target.value); if (candidate) chooseMapping(candidate); }}><option value="">Choose your users table</option>{candidates.map((candidate) => <option key={resourceKey(candidate)} value={resourceKey(candidate)}>{candidate.schema}.{candidate.relation}</option>)}</select></label>}
    {resources.length > 0 && <form onSubmit={(event) => void connect(event)}>
      <label>Database email<input type="email" value={email} autoComplete="email" onChange={(event) => setEmail(event.target.value)} required disabled={busy || disabled} /></label>
      <p className="muted">Must match Microsoft email: {verifiedEmail || 'unavailable'}.</p>
      <p>Selected roles can search every row using the listed fields. Use Advanced for limits by user or team.</p>
      <label>Find a table<input type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Table name" /></label>
      <div className="quick-tables">{resources.filter((table) => `${table.schema}.${table.relation}`.toLowerCase().includes(filter.toLowerCase())).map((table) => {
        const selection = selected.find((item) => resourceKey(item) === resourceKey(table));
        const profile = table.searchProfile!;
        const fields = [...new Set([profile.keyColumn,profile.labelColumn,...profile.searchColumns,...profile.returnColumns.map((column) => column.name)])];
        return <article className="query-entry" key={resourceKey(table)}>
          <label className="source-toggle"><input type="checkbox" checked={!!selection} disabled={busy || disabled || (!selection && selected.length >= 20)} onChange={(event) => toggleTable(table,event.target.checked)} />Search {table.schema}.{table.relation}</label>
          {selection && <fieldset disabled={busy || disabled}><legend>Roles with access</legend><div className="role-choices">{roles.map((role) => <label className="source-toggle" key={role}><input type="checkbox" checked={selection.roles.includes(role)} onChange={(event) => toggleRole(table,role,event.target.checked)} />{role}</label>)}</div></fieldset>}
          <details><summary>Search fields ({fields.length})</summary><p className="muted">{fields.join(', ')}</p></details>
        </article>;
      })}</div>
      {selected.some((table) => !table.roles.includes(currentRole)) && <p role="status">Include your role on each selected table so your account can test it before connecting.</p>}
      <button type="submit" disabled={busy || disabled || !validSelection || !verifiedEmail}>{busy ? 'Connecting…' : 'Save and connect'}</button>
    </form>}
    {message && <p role="status">{message}</p>}
    <button type="button" disabled={busy || disabled} onClick={() => setRevision((value) => value + 1)}>Refresh detected tables and roles</button>
  </div>;
}
