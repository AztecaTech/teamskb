export function encodeRelationChoice(schema, relation) {
  return JSON.stringify([schema, relation]);
}

export function decodeRelationChoice(value) {
  try {
    const decoded = JSON.parse(value);
    return Array.isArray(decoded) && decoded.length === 2 && decoded.every((part) => typeof part === 'string') ? decoded : null;
  } catch {
    return null;
  }
}
