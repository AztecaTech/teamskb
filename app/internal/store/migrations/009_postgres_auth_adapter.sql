CREATE TABLE postgres_adapter_profile_tests (
 tenant_id TEXT NOT NULL,
 object_id TEXT NOT NULL,
 email TEXT NOT NULL,
 tool_id TEXT NOT NULL,
 profile_generation TEXT NOT NULL,
 adapter_generation TEXT NOT NULL,
 user_id TEXT NOT NULL,
 database_role TEXT NOT NULL,
 permission_version TEXT NOT NULL,
 tested_at TEXT NOT NULL,
 outcome TEXT NOT NULL,
 PRIMARY KEY(tenant_id,object_id,tool_id)
);
