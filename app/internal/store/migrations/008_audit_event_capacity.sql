CREATE TABLE audit_event_state (id INTEGER PRIMARY KEY CHECK(id=1), event_count INTEGER NOT NULL CHECK(event_count>=0));
INSERT INTO audit_event_state(id,event_count) SELECT 1,COUNT(*) FROM audit_events;
