ALTER TABLE identity_bindings RENAME TO identity_bindings_v1;
CREATE TABLE identity_bindings (
  tenant_id TEXT NOT NULL,
  object_id TEXT NOT NULL,
  verified_email TEXT NOT NULL,
  database_identity TEXT NOT NULL,
  reviewed_by TEXT NOT NULL,
  reviewed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, object_id)
);
INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at)
SELECT tenant_id,object_id,verified_email,'',reviewed_by,reviewed_at FROM identity_bindings_v1;
DROP TABLE identity_bindings_v1;
CREATE UNIQUE INDEX identity_bindings_email_idx ON identity_bindings(tenant_id,verified_email) WHERE verified_email<>'';
ALTER TABLE query_tools ADD COLUMN description TEXT NOT NULL DEFAULT '';
DELETE FROM source_boundaries WHERE source_id='user-postgres';
DELETE FROM query_tools WHERE tool_id='knowledge_search';
