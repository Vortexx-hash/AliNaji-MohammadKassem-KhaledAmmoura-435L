import logging
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from shared.config import Settings
from shared.database import Database


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditOutbox:
    def __init__(self, db: Database, settings: Settings, service: str, transport=None):
        self.db, self.settings, self.service = db, settings, service
        self.transport = transport

    def record(self, conn, user_id, action, description, severity="Information"):
        conn.execute("INSERT INTO audit_outbox VALUES (?,?,?,?,?,?,?)", (
            str(uuid4()), user_id, action, description, utcnow(), severity, self.service))

    def denied(self, user_id, action, description):
        with self.db.connect() as conn:
            self.record(conn, user_id, action, description, "Warning")
        self.flush()

    def flush(self) -> int:
        """At-least-once delivery. Sink must deduplicate the Idempotency-Key header."""
        if not self.settings.audit_post_url or not self.settings.audit_service_token:
            return 0
        with self.db.connect() as conn:
            rows = conn.execute("""SELECT o.* FROM audit_outbox o LEFT JOIN audit_delivery d
                ON o.event_id=d.event_id WHERE d.event_id IS NULL ORDER BY o.timestamp LIMIT 100""").fetchall()
        sent = 0
        with httpx.Client(timeout=3, follow_redirects=False, transport=self.transport) as client:
            for row in rows:
                event = dict(row)
                event_id = event.pop("event_id")
                try:
                    response = client.post(self.settings.audit_post_url, json=event, headers={
                        "Authorization": f"Bearer {self.settings.audit_service_token}",
                        "Idempotency-Key": event_id,
                    })
                    response.raise_for_status()
                except httpx.HTTPError:
                    logging.getLogger(__name__).warning("Audit delivery deferred for %s", event_id)
                    break
                with self.db.connect() as conn:
                    conn.execute("INSERT OR IGNORE INTO audit_delivery VALUES (?,?)", (event_id, utcnow()))
                sent += 1
        return sent
