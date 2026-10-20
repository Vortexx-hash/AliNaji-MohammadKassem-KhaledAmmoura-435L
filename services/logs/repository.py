from datetime import timezone

from fastapi import HTTPException

from shared.audit import AuditOutbox, utcnow

INSERT = "INSERT INTO logs (event_id,user_id,action,description,timestamp,severity,related_service) VALUES (?,?,?,?,?,?,?)"


class LogWriter(AuditOutbox):
    """The Logs service is the audit sink, so its own events are written directly to the logs table."""

    def record(self, conn, user_id, action, description, severity="Information"):
        conn.execute(INSERT, (None, user_id, action, description, utcnow(), severity, self.service))

    def flush(self) -> int:
        return 0


class LogRepository:
    def __init__(self, db, audit):
        self.db, self.audit = db, audit

    def create(self, data, event_id=None):
        """Returns (record, created). A repeated Idempotency-Key returns the stored record."""
        timestamp = data.timestamp.astimezone(timezone.utc).isoformat() if data.timestamp else utcnow()
        user_id = None if data.user_id is None else str(data.user_id)
        with self.db.connect() as conn:
            cursor = conn.execute(INSERT + " ON CONFLICT(event_id) DO NOTHING", (
                event_id, user_id, data.action, data.description, timestamp, data.severity.value, data.related_service))
            if cursor.rowcount == 0:
                return dict(conn.execute("SELECT * FROM logs WHERE event_id=?", (event_id,)).fetchone()), False
            return dict(conn.execute("SELECT * FROM logs WHERE id=?", (cursor.lastrowid,)).fetchone()), True

    def get(self, log_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM logs WHERE id=?", (log_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Log record not found")
        return dict(row)

    def list(self, filters=None):
        clauses, params = [], []
        for key, value in (filters or {}).items():
            if key == "date":
                clauses.append("substr(timestamp, 1, 10) = ?")
            elif key in {"action", "related_service"}:
                clauses.append(f"{key} = ? COLLATE NOCASE")
            elif key in {"user_id", "severity"}:
                clauses.append(f"{key} = ?")
            else:
                raise ValueError("Unsupported search field")
            params.append(value)
        sql = "SELECT * FROM logs" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        with self.db.connect() as conn:
            return [dict(row) for row in conn.execute(sql + " ORDER BY timestamp, id", params)]

    def delete(self, log_id, user_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT action, user_id FROM logs WHERE id=?", (log_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Log record not found")
            conn.execute("DELETE FROM logs WHERE id=?", (log_id,))
            self.audit.record(conn, user_id, "LOG_DELETED",
                              f"Deleted log {log_id} ({row['action']} by user {row['user_id']})", "Warning")
