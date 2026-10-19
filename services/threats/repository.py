import sqlite3

from fastapi import HTTPException

from shared.audit import utcnow


class ThreatRepository:
    def __init__(self, db, audit):
        self.db, self.audit = db, audit

    def create(self, data, user_id):
        try:
            with self.db.connect() as conn:
                cursor = conn.execute("""INSERT INTO threats
                    (threat_type,threat_value,description,severity,source,date_added) VALUES (?,?,?,?,?,?)""",
                    (data.threat_type.value, data.threat_value, data.description, data.severity.value,
                     data.source, utcnow()))
                row = conn.execute("SELECT * FROM threats WHERE id=?", (cursor.lastrowid,)).fetchone()
                self.audit.record(conn, user_id, "THREAT_CREATED", f"Created threat {row['id']}")
        except sqlite3.IntegrityError as exc:
            if "UNIQUE constraint" in str(exc):
                raise HTTPException(409, "A threat with this type and value already exists") from exc
            raise
        self.audit.flush()
        return dict(row)

    def get(self, threat_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Threat indicator not found")
        return dict(row)

    def list(self, filters=None):
        clauses, params = [], []
        for key, value in (filters or {}).items():
            # Column names come only from the validated model; values are always bound.
            if key not in {"threat_type", "threat_value", "severity", "source"}:
                raise ValueError("Unsupported search field")
            if value is not None:
                clauses.append(f"{key} = ? COLLATE NOCASE")
                params.append(value)
        sql = "SELECT * FROM threats" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        with self.db.connect() as conn:
            return [dict(row) for row in conn.execute(sql + " ORDER BY id", params)]

    def update(self, threat_id, data, user_id):
        changes = data.model_dump(mode="json", exclude_unset=True)
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Threat indicator not found")
            conn.execute("UPDATE threats SET " + ",".join(f"{key}=?" for key in changes) + " WHERE id=?",
                         [*changes.values(), threat_id])
            self.audit.record(conn, user_id, "THREAT_UPDATED", f"Updated threat {threat_id}")
            result = dict(conn.execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone())
        self.audit.flush()
        return result

    def delete(self, threat_id, user_id):
        with self.db.connect() as conn:
            if conn.execute("DELETE FROM threats WHERE id=?", (threat_id,)).rowcount == 0:
                raise HTTPException(404, "Threat indicator not found")
            self.audit.record(conn, user_id, "THREAT_DELETED", f"Deleted threat {threat_id}")
        self.audit.flush()
