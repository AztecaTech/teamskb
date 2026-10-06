ALTER TABLE postgres_profile_tests ADD COLUMN binding_email TEXT NOT NULL DEFAULT '';
ALTER TABLE postgres_profile_tests ADD COLUMN binding_reviewed_at TEXT NOT NULL DEFAULT '';
ALTER TABLE postgres_profile_tests ADD COLUMN credential_generation TEXT NOT NULL DEFAULT '';
ALTER TABLE postgres_profile_tests ADD COLUMN profile_generation TEXT NOT NULL DEFAULT '';
