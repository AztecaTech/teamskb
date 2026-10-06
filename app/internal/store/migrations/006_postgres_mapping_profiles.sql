ALTER TABLE query_tools ADD COLUMN profile_config BLOB NOT NULL DEFAULT '{}';
CREATE TABLE postgres_login_claims (
  tenant_id TEXT NOT NULL,
  database_identity TEXT NOT NULL,
  object_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, database_identity),
  UNIQUE (tenant_id, object_id)
);
INSERT OR IGNORE INTO postgres_login_claims(tenant_id,database_identity,object_id)
SELECT tenant_id,database_identity,object_id FROM identity_bindings
WHERE database_identity<>''
GROUP BY tenant_id,database_identity HAVING COUNT(*)=1;
CREATE TABLE postgres_profile_tests (
  tenant_id TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  profile_version INTEGER NOT NULL,
  object_id TEXT NOT NULL,
  database_identity TEXT NOT NULL,
  schema_fingerprint TEXT NOT NULL,
  tested_at TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('passed','failed')),
  error_category TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, tool_id, profile_version, object_id)
);
