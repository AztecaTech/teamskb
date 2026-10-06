CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE admin_assignments (tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, object_id));
CREATE TABLE identity_bindings (tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, verified_email TEXT NOT NULL, database_role TEXT NOT NULL, reviewed_by TEXT NOT NULL, reviewed_at TEXT NOT NULL, PRIMARY KEY (tenant_id, object_id));
CREATE TABLE source_boundaries (source_id TEXT PRIMARY KEY, kind TEXT NOT NULL, canonical_boundary TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)));
CREATE TABLE query_tools (tool_id TEXT PRIMARY KEY, version INTEGER NOT NULL, fixed_sql TEXT NOT NULL, parameter_schema BLOB NOT NULL, output_columns BLOB NOT NULL, approval_record TEXT NOT NULL);
CREATE TABLE encrypted_secrets (secret_id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE usage_counters (period_utc TEXT NOT NULL, subject_id TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(period_utc, subject_id));
CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, request_id TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, details BLOB NOT NULL);
CREATE TABLE bridge_nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
