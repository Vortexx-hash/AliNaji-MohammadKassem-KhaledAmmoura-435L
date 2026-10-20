-- Security Audit Logging (Mohamed Kassem). Records are append-only: no UPDATE is ever allowed.
-- user_id is the actor's identity reference (NULL when unknown, e.g. a failed login for a missing account).
-- event_id stores the producer's Idempotency-Key so retried deliveries are stored once.
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    user_id TEXT,
    action TEXT NOT NULL CHECK(length(trim(action)) BETWEEN 1 AND 255),
    description TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 4000),
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Information','Warning','Error','Critical')),
    related_service TEXT NOT NULL CHECK(length(trim(related_service)) BETWEEN 1 AND 255)
);
CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE TRIGGER IF NOT EXISTS logs_no_update
BEFORE UPDATE ON logs BEGIN SELECT RAISE(ABORT, 'Audit logs cannot be modified'); END;
