"""Verify actual running owned services and save request/response evidence without bearer tokens."""
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

from scripts.dev_tokens import issue
from scripts.seed_owned import load_local_env
from shared.auth import Role
from shared.config import Settings


def main():
    load_local_env()
    settings = Settings.from_env()
    headers = {"Authorization": "Bearer " + issue(settings, Role.ADMIN.value, "local-verification")}
    executions = []
    with httpx.Client(headers=headers, timeout=10) as client:
        for port in [8004, 8007, 8006]:
            response = client.get(f"http://127.0.0.1:{port}/AliNaji/health")
            assert response.status_code == 200
        for kind, table in [
            ("threats", "threats"),
            ("vulnerabilities", "vulnerabilities"),
        ]:
            url = f"http://127.0.0.1:8006/AliNaji/reports/{kind}"
            response = client.get(url)
            assert response.status_code == 200, response.text
            report = response.json()
            # Identifiers below are fixed script constants, never user input.
            with sqlite3.connect(settings.data_dir / f"{kind}.db") as conn:
                conn.row_factory = sqlite3.Row
                records = [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]
                assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
            assert report[f"total_{kind}"] == len(records)
            by_severity = Counter(row["severity"] for row in records)
            assert all(count == by_severity.get(severity, 0) for severity, count in report[f"{kind}_by_severity"].items())
            executions.append({"method": "GET", "url": url, "status": response.status_code,
                               "response": report, "database_row_count": len(records), "matches_database": True})
            print(f"{kind}: report total {len(records)} matches actual SQLite records and severity groups")
        if not settings.sources.get("users"):
            url = "http://127.0.0.1:8006/AliNaji/reports/summary"
            response = client.get(url)
            assert response.status_code == 503
            executions.append({"method": "GET", "url": url, "status": 503, "response": response.json(),
                               "reason": "Users service not configured; no fabricated summary returned"})
        if not settings.asset_detail_url:
            url = "http://127.0.0.1:8007/AliNaji/vulnerabilities"
            body = {"title": "Verification probe", "description": "Must fail without a real asset service",
                    "cve_identifier": "CVE-2025-12345", "cvss_score": 8.1, "severity": "High",
                    "affected_asset_id": 1, "discovery_source": "Local verification"}
            response = client.post(url, json=body)
            assert response.status_code == 503
            executions.append({"method": "POST", "url": url, "request": body, "status": 503,
                               "response": response.json(), "reason": "No unverified asset association accepted"})
    target = Path("evidence/local/live-verification.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"executed_at": datetime.now(timezone.utc).isoformat(),
                                 "environment": "Actual local services and SQLite databases; no mock upstream services",
                                 "executions": executions}, indent=2), encoding="utf-8")
    print(f"Saved actual responses to {target}; this is CLI evidence, not a Postman screenshot")


if __name__ == "__main__":
    main()
