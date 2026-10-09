import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { resourceKey } from './types';
import type {
  IdentityAttributes, PermissionApi, PermissionPreview, PermissionResource,
  PermissionResourcePage, PermissionSource, ReadRule, ResourceReference,
} from './types';

type Options = {
  api: PermissionApi;
  identityRelation: ResourceReference;
  subjectKey: string;
  currentLabel?: string;
  permissionSource?: PermissionSource;
  onChange: (rules: ReadRule[], claims: IdentityAttributes) => void;
  onResourceSelected: (schema: string, relation: string) => void;
};

const automaticResourcePages = 4;

export function usePermissionDiscovery(options: Options) {
  const [resources, setResources] = useState<PermissionResource[]>([]);
  const [cursor, setCursor] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [preview, setPreview] = useState<PermissionPreview | null>(null);
  const generation = useRef(0);
  const source = options.permissionSource ?? 'internal';
  const latest = useRef({ ...options, cursor });

  // Parent callbacks can close over an edited adapter. Use the latest committed
  // callbacks without restarting discovery on every field/checkbox edit.
  useLayoutEffect(() => { latest.current = { ...options, cursor }; });

  const load = useCallback(async (append = false) => {
    const requestGeneration = ++generation.current;
    const isCurrent = () => requestGeneration === generation.current;
    setBusy(true);
    try {
      if (!append) {
        const response = await latest.current.api('/api/admin/postgres/auth/permissions');
        const result = await response.json() as PermissionPreview;
        if (!isCurrent()) return;

        if (source === 'internal' && result.mode === 'external') {
          setPreview({ configured: true, mode: 'internal' });
          setMessage('The internal adapter is selected. Save its mapping draft before checking saved permissions. Configure and review its own resource rules; external per-user snapshots are not reused as label grants.');
        } else if (result.mode !== 'external') {
          setPreview(result);
          if (!response.ok) {
            setMessage(`Saved permission check could not complete (${result.error || 'unknown'}). Review the mapping below; this result does not enable search.`);
          } else if (result.rules?.length) {
            const first = result.rules[0];
            latest.current.onResourceSelected(first.schema, first.relation);
            setMessage(`Reused ${result.rules.length} reviewed resource rule${result.rules.length === 1 ? '' : 's'} from IQ Knowledge for database user ${result.userId}, label ${result.label}. The first permitted resource is selected for a search profile. You can edit these rules below.`);
          } else {
            setMessage('The permission adapter runs inside IQ Knowledge. Choose permitted fields and row access once, then save. Matched users reuse those configured rules; metadata and role labels alone grant nothing.');
          }
        } else {
          setPreview(result);
          if (!response.ok) {
            setMessage(`Automatic permission lookup could not complete (${result.error || 'unknown'}). The explicitly configured external source must resolve this account; manual selections cannot override it.`);
          } else if (result.configured && result.rules?.length) {
            latest.current.onChange(result.rules, result.claimColumns || {});
            const first = result.rules[0];
            latest.current.onResourceSelected(first.schema, first.relation);
            setMessage(`Allowed fields and row access selected automatically for database user ${result.userId}, label ${result.label}. The first permitted resource is selected for a search profile; you can choose another below. Save permissions and continue.`);
          } else {
            setMessage('The explicitly configured external source has not supplied readable resources for this account.');
          }
          // External authority supplies resources itself. Never scan service
          // metadata as a fallback, including after an external denial.
          return;
        }
      }

      let next = append ? latest.current.cursor : '';
      for (let pageNumber = 0; pageNumber < automaticResourcePages; pageNumber++) {
        const response = await latest.current.api(`/api/admin/postgres/auth/resources${next}`);
        const page = await response.json() as PermissionResourcePage;
        if (!isCurrent()) return;
        if (!response.ok) throw new Error(`Resource discovery failed (${page.error || 'unknown'}).`);

        const replace = !append && pageNumber === 0;
        setResources((current) => {
          if (replace) return page.resources;
          const updatedKeys = new Set(page.resources.map(resourceKey));
          return [...current.filter((item) => !updatedKeys.has(resourceKey(item))), ...page.resources];
        });
        const previous = next;
        next = page.nextSchema
          ? `?afterSchema=${encodeURIComponent(page.nextSchema)}&afterName=${encodeURIComponent(page.nextName || '')}`
          : '';
        setCursor(next);
        if (!next || next === previous) break;
      }
    } catch (error) {
      if (isCurrent()) setMessage(error instanceof Error ? error.message : 'Permission discovery failed.');
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }, [source]);

  useEffect(() => {
    setPreview(null);
    setResources([]);
    setCursor('');
    void load();
    return () => { generation.current++; };
  }, [options.identityRelation.schema, options.identityRelation.relation, options.subjectKey, options.currentLabel, load]);

  return { resources, cursor, busy, message, setMessage, preview, load };
}
