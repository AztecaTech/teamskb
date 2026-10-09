import { useState } from 'react';
import IdentityAttributesEditor from './permissions/IdentityAttributesEditor';
import PermissionRuleEditor from './permissions/PermissionRuleEditor';
import { usePermissionDiscovery } from './permissions/usePermissionDiscovery';
import { resourceKey, ruleKey } from './permissions/types';
import type {
  IdentityAttributes, PermissionApi, PermissionPreview, PermissionSource,
  ReadRule, ResourceReference,
} from './permissions/types';

type Props = {
  labels: string[];
  permissionSource?: PermissionSource;
  onUseInternal: () => void;
  currentLabel?: string;
  rules: ReadRule[];
  claims: IdentityAttributes;
  identityRelation: ResourceReference;
  subjectKey: string;
  disabled: boolean;
  onChange: (rules: ReadRule[], claims: IdentityAttributes) => void;
  onResourceSelected: (schema: string, relation: string) => void;
  api: PermissionApi;
};

function ExternalPermissionSummary({ preview, message, disabled, onRefresh, onUseInternal, onSelect }: {
  preview: PermissionPreview;
  message: string;
  disabled: boolean;
  onRefresh: () => void;
  onUseInternal: () => void;
  onSelect: (resource: ResourceReference) => void;
}) {
  return <div id="application-permissions" className="query-entry">
    <h4>Automatically selected permissions</h4>
    <p role="status">{message}</p>
    <p>Fields and row access come from your explicitly selected external source. The server rechecks its decisions for every database operation.</p>
    <button type="button" disabled={disabled} onClick={onRefresh}>Refresh my permissions</button>
    <button type="button" disabled={disabled} onClick={onUseInternal}>Use the adapter inside IQ Knowledge</button>
    {preview.rules?.map((rule) => <div className="query-entry" key={resourceKey(rule)}>
      <strong>{rule.schema}.{rule.relation}</strong>
      <p>Permitted fields: {rule.fields.join(', ')}.</p>
      <p>Row access: {rule.scope.kind}{rule.scope.column ? ` on ${rule.scope.column}` : ''}.</p>
      <button type="button" disabled={disabled} onClick={() => onSelect(rule)}>Search this resource</button>
    </div>)}
  </div>;
}

export default function ApplicationPermissionEditor(props: Props) {
  const { labels, currentLabel, rules, claims, identityRelation, disabled, onChange, onResourceSelected } = props;
  const { resources, cursor, busy, message, setMessage, preview, load } = usePermissionDiscovery(props);
  const [resourceFilter, setResourceFilter] = useState('');
  const [editingRule, setEditingRule] = useState('');
  const resourcesByKey = new Map(resources.map((resource) => [resourceKey(resource), resource]));
  const identityResource = resourcesByKey.get(resourceKey(identityRelation));
  const detectedLabels = [...new Set([
    ...(currentLabel ? [currentLabel] : []),
    ...(preview?.label ? [preview.label] : []),
    ...labels,
    ...rules.map((rule) => rule.label),
  ])];
  const currentRules = rules.filter((rule) => rule.label === currentLabel);
  const availableResources = resources.filter((resource) =>
    resourceKey(resource) !== resourceKey(identityRelation) &&
    `${resource.schema}.${resource.relation}`.toLowerCase().includes(resourceFilter.toLowerCase()),
  );

  function updateRule(key: string, change: Partial<ReadRule>) {
    onChange(rules.map((rule) => ruleKey(rule) === key
      ? { ...rule, ...change, reviewed: change.reviewed ?? false }
      : rule), claims);
  }

  function addResource(label: string, key: string) {
    const resource = resourcesByKey.get(key);
    if (!resource) return;
    const draft: ReadRule = {
      label, schema: resource.schema, relation: resource.relation,
      fields: [], scope: { kind: 'pending' }, reviewed: false,
    };
    onChange([...rules, draft], claims);
    setEditingRule(ruleKey(draft));
    if (label === currentLabel) onResourceSelected(resource.schema, resource.relation);
  }

  function changeAttribute(name: string, column?: string) {
    const nextClaims = { ...claims };
    if (column === undefined) delete nextClaims[name];
    else nextClaims[name] = column;
    onChange(rules.map((rule) => rule.scope.claim === name
      ? { ...rule, reviewed: false }
      : rule), nextClaims);
  }

  function selectProfileResource(resource: ResourceReference) {
    onResourceSelected(resource.schema, resource.relation);
    setMessage(`Selected ${resource.schema}.${resource.relation} for the search profile. Save permissions and continue below.`);
  }

  if (preview?.configured && preview.mode === 'external') {
    return <ExternalPermissionSummary
      preview={preview}
      message={message}
      disabled={disabled || busy}
      onRefresh={() => void load()}
      onUseInternal={props.onUseInternal}
      onSelect={selectProfileResource}
    />;
  }

  return <div id="application-permissions" className="query-entry">
    <h4>Permission adapter inside IQ Knowledge</h4>
    {currentLabel && <p role="status">
      Your matched database label is <strong>{currentLabel}</strong>.{' '}
      {currentRules.some((rule) => rule.reviewed)
        ? 'A reviewed resource rule is configured. Save permissions to continue to search setup.'
        : currentRules.length
          ? 'Finish the fields and row access for your resource, then mark the rule reviewed.'
          : 'No resource is configured for this label yet. Choose a table under this label to begin.'}
    </p>}
    <p>The deployment URI connects to PostgreSQL. Your verified Microsoft email identifies one active database user. The rules saved here restrict that user's fields and rows before retrieval.</p>
    <p className="muted">Roles, tables, columns and membership mappings are configuration stored only in IQ Knowledge. No CRM backend or PostgreSQL changes are required. Review rules against the existing permissions; custom backend or JSON rules cannot be inferred from metadata.</p>
    <fieldset disabled={disabled || busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <div className="button-row">
        <button type="button" onClick={() => void load()}>Check saved permissions and discover resources</button>
        {cursor && <button type="button" onClick={() => void load(true)}>Load more resources</button>}
      </div>
      {message && <p role="status">{message}</p>}
      <label>
        Find a resource
        <input type="search" value={resourceFilter} onChange={(event) => setResourceFilter(event.target.value)} placeholder="Filter loaded tables by schema or name" />
      </label>
      <p className="muted">{resources.length} resources loaded{cursor ? '; load more if your table is missing' : ''}.</p>
      <IdentityAttributesEditor
        key={resourceKey(identityRelation)}
        claims={claims}
        resource={identityResource}
        onAdd={changeAttribute}
        onRemove={(name) => changeAttribute(name)}
      />
      {detectedLabels.map((label) => <div className="query-entry" key={label}>
        <h4>{label}{label === currentLabel ? ' · Your database label' : ''}</h4>
        <label>
          Add readable resource
          <select value="" onChange={(event) => addResource(label, event.target.value)}>
            <option value="">Choose your first table</option>
            {availableResources.map((resource) => <option
              key={resourceKey(resource)}
              value={resourceKey(resource)}
              disabled={rules.some((rule) => rule.label === label && resourceKey(rule) === resourceKey(resource))}
            >{resource.schema}.{resource.relation}</option>)}
          </select>
        </label>
        {rules.filter((rule) => rule.label === label).map((rule) => <PermissionRuleEditor
          key={ruleKey(rule)}
          rule={rule}
          resource={resourcesByKey.get(resourceKey(rule))}
          claims={claims}
          initiallyOpen={editingRule === ruleKey(rule)}
          isCurrentLabel={label === currentLabel}
          onUpdate={(change) => updateRule(ruleKey(rule), change)}
          onRemove={() => onChange(rules.filter((item) => ruleKey(item) !== ruleKey(rule)), claims)}
          onSelect={() => selectProfileResource(rule)}
        />)}
      </div>)}
      {!detectedLabels.length && <p>Detect the user mapping and its role values to configure resource permissions.</p>}
      <p>Use “Save permissions and continue” below. The app checks your account and opens searchable metadata. Other labels remain unavailable until their own rules are configured.</p>
    </fieldset>
  </div>;
}
