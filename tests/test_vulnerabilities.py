import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from shared.auth import Role
from shared.upstream import UpstreamClient

BASE = "/AliNaji/vulnerabilities"


def test_crud_search_full_lifecycle(vulnerability_client, auth, vulnerability, settings):
    c = vulnerability_client
    response = c.post(BASE, json=vulnerability, headers=auth())
    assert response.status_code == 201
    item = response.json()
    path = f"{BASE}/{item['id']}"
    assert item["status"] == "Open" and item["resolution_date"] is None
    assert c.get(BASE, headers=auth()).json() == [item]
    assert c.get(path, headers=auth()).json() == item
    for filters in [{"cve_identifier": "CVE-2025-12345"}, {"severity": "High"},
                    {"affected_asset_id": 7}, {"status": "Open"},
                    {"severity": "High", "status": "Open", "affected_asset_id": 7}]:
        assert c.get(BASE + "/search", params=filters, headers=auth()).json() == [item]
    assert c.get(BASE + "/search?status=Closed", headers=auth()).json() == []
    assert c.put(path, json={"status": "Closed"}, headers=auth()).status_code == 409
    resolution = None
    for status in ["Under Investigation", "In Progress", "Resolved", "Closed"]:
        response = c.put(path, json={"status": status, "cvss_score": 9.1, "severity": "Critical"}, headers=auth(Role.ANALYST))
        assert response.status_code == 200
        assert response.json()["status"] == status
        if status == "Resolved":
            resolution = response.json()["resolution_date"]
            assert resolution
        if status == "Closed":
            assert response.json()["resolution_date"] == resolution
    assert c.put(path, json={"status": "Open"}, headers=auth()).status_code == 409
    assert c.put(path, json={"status": "Closed"}, headers=auth()).status_code == 200
    with sqlite3.connect(settings.data_dir / "vulnerabilities.db") as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT affected_asset_id,status FROM vulnerabilities").fetchone() == (7, "Closed")
        assert conn.execute("SELECT asset_id FROM asset_references").fetchone()[0] == 7
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE vulnerabilities SET status='Open'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM asset_references")
    assert c.delete(path, headers=auth()).status_code == 204
    assert c.get(path, headers=auth()).status_code == 404
    assert c.delete(path, headers=auth()).status_code == 404


@pytest.mark.parametrize("change", [
    {"title": " "}, {"description": ""}, {"cve_identifier": "12345"},
    {"cve_identifier": "CVE-2025-123"}, {"cvss_score": -0.1}, {"cvss_score": 10.1},
    {"cvss_score": "8.1"}, {"cvss_score": True}, {"affected_asset_id": 0},
    {"affected_asset_id": True}, {"affected_asset_id": "7"}, {"severity": "severe"},
    {"status": "Resolved"}, {"discovery_source": " "}, {"unknown": 1},
])
def test_validation(vulnerability_client, auth, vulnerability, change):
    vulnerability.update(change)
    response = vulnerability_client.post(BASE, json=vulnerability, headers=auth())
    assert response.status_code == 422 and response.json()["status"] == "error"


@pytest.mark.parametrize("role,read,create,update,delete", [
    (Role.ADMIN, 200, 201, 200, 204), (Role.ANALYST, 200, 403, 200, 403),
    (Role.AUDITOR, 200, 403, 403, 403), (Role.USER, 403, 403, 403, 403),
])
def test_roles(vulnerability_client, auth, vulnerability, role, read, create, update, delete):
    c = vulnerability_client
    item = c.post(BASE, json=vulnerability, headers=auth()).json()
    path = f"{BASE}/{item['id']}"
    assert c.get(BASE, headers=auth(role)).status_code == read
    assert c.get(path, headers=auth(role)).status_code == read
    assert c.get(BASE + "/search", headers=auth(role)).status_code == read
    assert c.post(BASE, json=vulnerability, headers=auth(role)).status_code == create
    assert c.put(path, json={"description": "Reassessed"}, headers=auth(role)).status_code == update
    assert c.delete(path, headers=auth(role)).status_code == delete


def test_missing_asset_and_dependency_failure(vulnerability_client, auth, vulnerability):
    c = vulnerability_client
    vulnerability["affected_asset_id"] = 99
    assert c.post(BASE, json=vulnerability, headers=auth()).status_code == 404
    for response in [httpx.Response(503), httpx.Response(200, json={"id": 100}),
                     httpx.Response(200, text="bad json"), httpx.Response(200, json=[]),
                     httpx.Response(200, json={"id": True})]:
        c.app.state.upstream = UpstreamClient(httpx.MockTransport(lambda request: response))
        assert c.post(BASE, json=vulnerability, headers=auth()).status_code == 503
    assert c.get(BASE, headers=auth()).json() == []


def test_resolution_dates_and_update_errors(vulnerability_client, auth, vulnerability):
    c = vulnerability_client
    item = c.post(BASE, json=vulnerability, headers=auth()).json()
    path = f"{BASE}/{item['id']}"
    now = datetime.now(timezone.utc).isoformat()
    for update in [{}, {"severity": None}, {"affected_asset_id": 99}, {"resolution_date": "2025-01-01T00:00:00"},
                   {"resolution_date": now}, {"status": "Unknown"}]:
        assert c.put(path, json=update, headers=auth()).status_code == 422
    for status in ["Under Investigation", "In Progress"]:
        assert c.put(path, json={"status": status}, headers=auth()).status_code == 200
    for date in ["2000-01-01T00:00:00Z", (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()]:
        assert c.put(path, json={"status": "Resolved", "resolution_date": date}, headers=auth()).status_code == 422
    date = datetime.now(timezone.utc).isoformat()
    response = c.put(path, json={"status": "Resolved", "resolution_date": date}, headers=auth())
    assert response.status_code == 200 and response.json()["resolution_date"] == date
    assert c.get(BASE + "/search?affected_asset_id=0", headers=auth()).status_code == 422
    assert c.get(BASE + "/search?typo=1", headers=auth()).status_code == 422
    assert c.get(BASE + "/0", headers=auth()).status_code == 422
    assert c.get(BASE + "/999999", headers=auth()).status_code == 404
    assert c.put(BASE + "/999999", json={"severity": "Low"}, headers=auth()).status_code == 404
