-- Transport storage for Ali Naji's services; NOT the teammate's Logs service.
CREATE TABLE IF NOT EXISTS audit_outbox (
    event_id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Information','Warning','Error','Critical')),
    related_service TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_delivery (
    event_id TEXT PRIMARY KEY REFERENCES audit_outbox(event_id) ON DELETE RESTRICT,
    delivered_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_outbox_no_update
BEFORE UPDATE ON audit_outbox BEGIN SELECT RAISE(ABORT, 'Audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_outbox_no_delete
BEFORE DELETE ON audit_outbox BEGIN SELECT RAISE(ABORT, 'Audit events are immutable'); END;
