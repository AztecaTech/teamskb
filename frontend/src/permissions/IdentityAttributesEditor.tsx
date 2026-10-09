import { useState } from 'react';
import type { IdentityAttributes, PermissionResource } from './types';

type Props = {
  claims: IdentityAttributes;
  resource?: PermissionResource;
  onAdd: (name: string, column: string) => void;
  onRemove: (name: string) => void;
};

export default function IdentityAttributesEditor({ claims, resource, onAdd, onRemove }: Props) {
  const [name, setName] = useState('');
  const [column, setColumn] = useState('');

  function addAttribute() {
    onAdd(name, column);
    setName('');
    setColumn('');
  }

  return <details>
    <summary>Additional identity attributes (optional)</summary>
    <p>For rules based on a native user name or organization ID, map an attribute to an existing column in the user relation. Values are read from the matched user, never entered by the search user.</p>
    {Object.entries(claims).map(([attribute, mappedColumn]) => <p key={attribute}>
      {attribute} → {mappedColumn}{' '}
      <button type="button" onClick={() => onRemove(attribute)}>Remove attribute</button>
    </p>)}
    <label>
      Attribute name
      <input value={name} maxLength={63} onChange={(event) => setName(event.target.value)} placeholder="Choose an attribute name" />
    </label>
    <label>
      Existing user column
      {resource ? <select value={column} onChange={(event) => setColumn(event.target.value)}>
        <option value="">Select column</option>
        {resource.scalarColumns?.map((field) => <option key={field} value={field}>{field}</option>)}
      </select> : <input
        value={column}
        maxLength={63}
        onChange={(event) => setColumn(event.target.value)}
        placeholder="Existing column name"
      />}
    </label>
    <button type="button" disabled={!name || !column} onClick={addAttribute}>Add identity attribute</button>
  </details>;
}
