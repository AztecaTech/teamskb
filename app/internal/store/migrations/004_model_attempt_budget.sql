CREATE TABLE model_attempt_counters (month_utc TEXT PRIMARY KEY, attempts INTEGER NOT NULL CHECK(attempts >= 0));
