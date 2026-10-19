from datetime import datetime, timezone

from fastapi import HTTPException

from services.vulnerabilities.models import VulnerabilityStatus
from shared.audit import utcnow

STATES = [state.value for state in VulnerabilityStatus]


class VulnerabilityRepository:
    def __init__(self, db, audit):
        self.db, self.audit = db, audit

    def create(self, data, asset, user_id):
        values = data.model_dump(mode="json")
        now = utcnow()
        with self.db.connect() as conn:
            conn.execute("""INSERT INTO asset_references VALUES (?,?,?) ON CONFLICT(asset_id)
                DO UPDATE SET asset_name=excluded.asset_name, verified_at=excluded.verified_at""",
                (asset["id"], str(asset.get("asset_name", asset.get("name", ""))), now))
            fields = [*values, "status", "creation_date"]
            cursor = conn.execute("INSERT INTO vulnerabilities (" + ",".join(fields) + ") VALUES ("
                                  + ",".join("?" for _ in fields) + ")", [*values.values(), "Open", now])
            row = dict(conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (cursor.lastrowid,)).fetchone())
            self.audit.record(conn, user_id, "VULNERABILITY_CREATED", f"Created vulnerability {row['id']} for asset {asset['id']}")
        self.audit.flush()
        return row

    def get(self, vulnerability_id):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Vulnerability not found")
        return dict(row)

    def list(self, filters=None):
        clauses, params = [], []
        for key, value in (filters or {}).items():
            if key not in {"cve_identifier", "severity", "affected_asset_id", "status"}:
                raise ValueError("Unsupported search field")
            if value is not None:
                clauses.append(f"{key} = ?")
                params.append(value)
        sql = "SELECT * FROM vulnerabilities" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        with self.db.connect() as conn:
            return [dict(row) for row in conn.execute(sql + " ORDER BY id", params)]

    def update(self, vulnerability_id, data, user_id):
        changes = data.model_dump(mode="json", exclude_unset=True)
        with self.db.connect() as conn:
            # Serialize read/validate/write to prevent concurrent requests skipping a state.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Vulnerability not found")
            target = changes.get("status", row["status"])
            if target != row["status"] and STATES.index(target) != STATES.index(row["status"]) + 1:
                raise HTTPException(409, "Allowed lifecycle: Open -> Under Investigation -> In Progress -> Resolved -> Closed")
            if "resolution_date" in changes and target not in ("Resolved", "Closed"):
                raise HTTPException(422, "Resolution date is only valid for Resolved or Closed vulnerabilities")
            if target in ("Resolved", "Closed"):
                resolution = data.resolution_date if "resolution_date" in changes else None
                if resolution is not None:
                    resolution = resolution.astimezone(timezone.utc)
                    if resolution < datetime.fromisoformat(row["creation_date"]) or resolution > datetime.now(timezone.utc):
                        raise HTTPException(422, "Resolution date must be between creation time and the current time")
                    changes["resolution_date"] = resolution.isoformat()
                elif row["resolution_date"] is None:
                    changes["resolution_date"] = utcnow()
            conn.execute("UPDATE vulnerabilities SET " + ",".join(f"{key}=?" for key in changes) + " WHERE id=?",
                         [*changes.values(), vulnerability_id])
            self.audit.record(conn, user_id, "VULNERABILITY_UPDATED", f"Updated vulnerability {vulnerability_id}; status {row['status']} -> {target}")
            result = dict(conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone())
        self.audit.flush()
        return result

    def delete(self, vulnerability_id, user_id):
        with self.db.connect() as conn:
            if conn.execute("DELETE FROM vulnerabilities WHERE id=?", (vulnerability_id,)).rowcount == 0:
                raise HTTPException(404, "Vulnerability not found")
            self.audit.record(conn, user_id, "VULNERABILITY_DELETED", f"Deleted vulnerability {vulnerability_id}")
        self.audit.flush()
