import sqlite3

import pytest

from shared.auth import Role

BASE = "/AliNaji/threats"


def test_crud_search_and_real_database(threat_client, auth, threat, settings):
    c = threat_client
    created = c.post(BASE, json=threat, headers=auth())
    assert created.status_code == 201
    item = created.json()
    assert item["id"] > 0 and item["date_added"]
    with sqlite3.connect(settings.data_dir / "threats.db") as db:
        assert db.execute("SELECT threat_value FROM threats").fetchone()[0] == threat["threat_value"]
    assert c.get(BASE, headers=auth()).json() == [item]
    assert c.get(f"{BASE}/{item['id']}", headers=auth()).json() == item
    for filters in [{"threat_type": "IP Address"}, {"severity": "High"}, {"source": "Lab sensor"},
                    {"threat_value": "203.0.113.8"}, {"severity": "High", "source": "Lab sensor"}]:
        assert c.get(BASE + "/search", params=filters, headers=auth()).json() == [item]
    assert c.get(BASE + "/search", params={"source": "absent"}, headers=auth()).json() == []
    updated = c.put(f"{BASE}/{item['id']}", json={"severity": "Critical"}, headers=auth())
    assert updated.status_code == 200 and updated.json()["severity"] == "Critical"
    assert updated.json()["date_added"] == item["date_added"]
    assert c.delete(f"{BASE}/{item['id']}", headers=auth()).status_code == 204
    assert c.get(f"{BASE}/{item['id']}", headers=auth()).status_code == 404
    with sqlite3.connect(settings.data_dir / "threats.db") as db:
        assert db.execute("SELECT count(*) FROM threats").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM audit_outbox").fetchone()[0] == 3
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE audit_outbox SET description='tampered'")


@pytest.mark.parametrize("kind,value,normalized", [
    ("Domain", "Example.COM.", "example.com"),
    ("IP Address", "2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
    ("File Hash", "AB" * 32, "ab" * 32),
    ("File Hash", "CD" * 64, "cd" * 64),
    ("Malware Signature", "LAB-SIGNATURE", "LAB-SIGNATURE"),
    ("Other Indicators", "test-indicator", "test-indicator"),
])
def test_canonical_duplicate_indicators(threat_client, auth, threat, kind, value, normalized):
    threat.update(threat_type=kind, threat_value=value)
    result = threat_client.post(BASE, json=threat, headers=auth())
    assert result.status_code == 201 and result.json()["threat_value"] == normalized
    threat["threat_value"] = normalized
    assert threat_client.post(BASE, json=threat, headers=auth()).status_code == 409


@pytest.mark.parametrize("change", [
    {"threat_type": "Invalid"}, {"threat_value": "999.1.1.1"},
    {"threat_type": "Domain", "threat_value": "https://example.com/path"},
    {"threat_type": "Domain", "threat_value": "192.0.2.1"},
    {"threat_type": "Domain", "threat_value": "-bad.example"},
    {"threat_type": "Domain", "threat_value": "bad.example.."},
    {"threat_type": "File Hash", "threat_value": "g" * 64},
    {"threat_type": "File Hash", "threat_value": "a" * 33},
    {"description": " "}, {"severity": "Severe"}, {"source": None}, {"unexpected": True},
])
def test_rejects_invalid_threats(threat_client, auth, threat, change):
    threat.update(change)
    response = threat_client.post(BASE, json=threat, headers=auth())
    assert response.status_code == 422 and response.json()["status"] == "error"


@pytest.mark.parametrize("role,read,search,write", [
    (Role.ADMIN, 200, 200, 201), (Role.ANALYST, 200, 200, 403),
    (Role.AUDITOR, 200, 403, 403), (Role.USER, 403, 403, 403),
])
def test_role_permissions(threat_client, auth, threat, role, read, search, write):
    c = threat_client
    assert c.get(BASE, headers=auth(role)).status_code == read
    assert c.get(BASE + "/search", headers=auth(role)).status_code == search
    assert c.post(BASE, json=threat, headers=auth(role)).status_code == write
    if role != Role.ADMIN:
        assert c.put(BASE + "/1", json={"severity": "Low"}, headers=auth(role)).status_code == 403
        assert c.delete(BASE + "/1", headers=auth(role)).status_code == 403


def test_auth_validation_and_sql_injection(threat_client, auth, threat, settings):
    c = threat_client
    for headers in [{}, {"Authorization": "Bearer fake"}, auth(status="Suspended"),
                    auth(status="Inactive"), auth(minutes=-1)]:
        assert c.get(BASE, headers=headers).status_code == 401
    assert c.post(BASE, json=threat, headers=auth()).status_code == 201
    assert c.get(BASE + "/search", params={"source": "' OR 1=1 --"}, headers=auth()).json() == []
    assert len(c.get(BASE, headers=auth()).json()) == 1
    for body in [{}, {"severity": None}, {"threat_value": "changed"}]:
        assert c.put(BASE + "/1", json=body, headers=auth()).status_code == 422
    assert c.get(BASE + "/0", headers=auth()).status_code == 422
    assert c.get(BASE + "/9999", headers=auth()).status_code == 404
    assert c.get(BASE + "/search?typo=true", headers=auth()).status_code == 422
    assert c.post(BASE, content="{bad", headers={**auth(), "Content-Type": "application/json"}).status_code == 422
    with sqlite3.connect(settings.data_dir / "threats.db") as db:
        assert db.execute("SELECT count(*) FROM audit_outbox WHERE action='AUTHENTICATION_FAILED'").fetchone()[0] == 5
