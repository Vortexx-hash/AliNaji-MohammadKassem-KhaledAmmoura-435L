from fastapi import HTTPException

from shared.audit import utcnow


class NotificationRepository:
    def __init__(self, db, audit):
        self.db, self.audit = db, audit

    def create(self, data, recipient, actor_id):
        values = data.model_dump(mode="json")
        now = utcnow()
        with self.db.connect() as conn:
            conn.execute("""INSERT INTO user_references VALUES (?,?,?) ON CONFLICT(user_id)
                DO UPDATE SET username=excluded.username, verified_at=excluded.verified_at""",
                (recipient["id"], str(recipient.get("username", "")), now))
            fields = [*values, "status", "creation_date"]
            cursor = conn.execute("INSERT INTO notifications (" + ",".join(fields) + ") VALUES ("
                                  + ",".join("?" for _ in fields) + ")", [*values.values(), "Unread", now])
            row = dict(conn.execute("SELECT * FROM notifications WHERE id=?", (cursor.lastrowid,)).fetchone())
            self.audit.record(conn, actor_id, "NOTIFICATION_CREATED",
                              f"Created {row['notification_type']} notification {row['id']} for user {row['user_id']}")
        self.audit.flush()
        return row

    def get(self, notification_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM notifications WHERE id=?", (notification_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Notification not found")
        return dict(row)

    def list(self, filters=None):
        clauses, params = [], []
        for key, value in (filters or {}).items():
            if key not in {"user_id", "notification_type", "severity", "status"}:
                raise ValueError("Unsupported search field")
            clauses.append(f"{key} = ?")
            params.append(value)
        sql = "SELECT * FROM notifications" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        with self.db.connect() as conn:
            return [dict(row) for row in conn.execute(sql + " ORDER BY id", params)]

    def mark_read(self, notification_id, actor_id):
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM notifications WHERE id=?", (notification_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Notification not found")
            if row["status"] == "Read":
                return dict(row)
            conn.execute("UPDATE notifications SET status='Read', read_date=? WHERE id=?", (utcnow(), notification_id))
            self.audit.record(conn, actor_id, "NOTIFICATION_READ", f"Marked notification {notification_id} as read")
            result = dict(conn.execute("SELECT * FROM notifications WHERE id=?", (notification_id,)).fetchone())
        self.audit.flush()
        return result

    def delete(self, notification_id, actor_id):
        with self.db.connect() as conn:
            if conn.execute("DELETE FROM notifications WHERE id=?", (notification_id,)).rowcount == 0:
                raise HTTPException(404, "Notification not found")
            self.audit.record(conn, actor_id, "NOTIFICATION_DELETED", f"Deleted notification {notification_id}")
        self.audit.flush()
