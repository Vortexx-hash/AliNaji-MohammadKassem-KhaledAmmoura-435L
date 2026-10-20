import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from scripts.dev_tokens import issue
from services.reports.models import ActivitySource
from shared.auth import Role

BASE = "/MohamedKassem/logs"


@pytest.fixture
def entry():
    return {"user_id": "5", "action": "MANUAL_REVIEW", "description": "Administrator reviewed firewall changes",
            "severity": "Information", "related_service": "Security Audit Logging"}


def logs_table(settings):
    with sqlite3.connect(settings.data_dir / "logs.db") as db:
        return db.execute("SELECT user_id, action, severity, related_service FROM logs ORDER BY id").fetchall()


def test_create_list_get_and_immutability(logs_client, auth, entry, settings):
    response = logs_client.post(BASE, json=entry, headers=auth())
    assert response.status_code == 201
    item = response.json()
    assert item["id"] > 0 and datetime.fromisoformat(item["timestamp"]).tzinfo is not None
    assert {k: item[k] for k in entry} == entry
    assert logs_client.get(BASE, headers=auth()).json() == [item]
    assert logs_client.get(f"{BASE}/{item['id']}", headers=auth()).json() == item
    assert logs_client.get(f"{BASE}/2147483647", headers=auth()).status_code == 404
    assert logs_client.put(f"{BASE}/{item['id']}", json=entry, headers=auth()).status_code == 405
    with sqlite3.connect(settings.data_dir / "logs.db") as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("UPDATE logs SET description='tampered'")


def test_unknown_actor_original_timestamp_and_idempotency(logs_client, auth, entry):
    original = "2026-10-01T08:30:00+03:00"
    response = logs_client.post(BASE, json={**entry, "user_id": None, "timestamp": original}, headers=auth())
    assert response.status_code == 201
    assert response.json()["user_id"] is None and response.json()["timestamp"] == "2026-10-01T05:30:00+00:00"
    headers = {**auth(), "Idempotency-Key": "event-123"}
    first = logs_client.post(BASE, json=entry, headers=headers)
    retry = logs_client.post(BASE, json={**entry, "description": "retried"}, headers=headers)
    assert first.status_code == 201 and retry.status_code == 200 and retry.json() == first.json()
    assert len(logs_client.get(BASE, headers=auth()).json()) == 2


@pytest.mark.parametrize("change", [
    {"severity": "Info"}, {"action": " "}, {"description": None}, {"related_service": ""}, {"user_id": 0},
    {"user_id": ""}, {"timestamp": "2026-10-01T08:30:00"}, {"timestamp": "not-a-date"}, {"unexpected": 1},
    {"timestamp": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
])
def test_rejects_invalid_logs(logs_client, auth, entry, change):
    response = logs_client.post(BASE, json={**entry, **change}, headers=auth())
    assert response.status_code == 422 and response.json()["status"] == "error"


def test_user_id_key_is_required(logs_client, auth, entry):
    del entry["user_id"]
    assert logs_client.post(BASE, json=entry, headers=auth()).status_code == 422


def test_search_and_logs_by_user(logs_client, auth, entry):
    rows = [{**entry}, {**entry, "user_id": 7, "action": "LOGIN_FAILED", "severity": "Warning",
                        "related_service": "Users and Identity Management"},
            {**entry, "user_id": "7", "timestamp": "2026-10-01T23:30:00+00:00"}]
    ids = [logs_client.post(BASE, json=row, headers=auth()).json()["id"] for row in rows]

    def search(**params):
        response = logs_client.get(BASE + "/search", params=params, headers=auth())
        assert response.status_code == 200
        return [row["id"] for row in response.json()]

    assert search(user_id="7") == [ids[2], ids[1]]
    assert search(action="login_failed") == [ids[1]]
    assert search(severity="Warning") == [ids[1]]
    assert search(related_service="users and identity management") == [ids[1]]
    assert search(date="2026-10-01") == [ids[2]]
    assert search(user_id="7", action="MANUAL_REVIEW") == [ids[2]]
    assert search(action="absent") == []
    assert sorted(search()) == ids
    for params in [{"severity": "Info"}, {"date": "01-10-2026"}, {"unknown": "x"}]:
        assert logs_client.get(BASE + "/search", params=params, headers=auth()).status_code == 422
    assert [row["id"] for row in logs_client.get(BASE + "/user/7", headers=auth()).json()] == [ids[2], ids[1]]
    response = logs_client.get(BASE + "/user/999", headers=auth())
    assert response.status_code == 200 and response.json() == []


@pytest.mark.parametrize("role,create,list_all,get,search,by_user,delete", [
    (Role.ADMIN, 201, 200, 200, 200, 200, 204),
    (Role.AUDITOR, 403, 200, 200, 200, 200, 403),
    (Role.ANALYST, 403, 403, 200, 200, 403, 403),
    (Role.USER, 403, 403, 403, 403, 403, 403),
])
def test_role_permissions(logs_client, auth, entry, role, create, list_all, get, search, by_user, delete):
    log_id = logs_client.post(BASE, json=entry, headers=auth()).json()["id"]
    headers = auth(role)
    assert logs_client.post(BASE, json=entry, headers=headers).status_code == create
    assert logs_client.get(BASE, headers=headers).status_code == list_all
    assert logs_client.get(f"{BASE}/{log_id}", headers=headers).status_code == get
    assert logs_client.get(BASE + "/search", headers=headers).status_code == search
    assert logs_client.get(BASE + "/user/5", headers=headers).status_code == by_user
    assert logs_client.delete(f"{BASE}/{log_id}", headers=headers).status_code == delete
    assert logs_client.get(BASE).status_code == 401


def test_own_events_are_written_to_logs_table(logs_client, auth, entry, settings):
    log_id = logs_client.post(BASE, json=entry, headers=auth()).json()["id"]
    assert logs_client.delete(f"{BASE}/{log_id}", headers=auth(Role.ANALYST, user_id="6")).status_code == 403
    assert logs_client.delete(f"{BASE}/{log_id}", headers=auth(user_id="1")).status_code == 204
    assert logs_client.get(f"{BASE}/{log_id}", headers=auth()).status_code == 404
    assert logs_client.delete(f"{BASE}/{log_id}", headers=auth()).status_code == 404
    assert logs_table(settings) == [("6", "PERMISSION_DENIED", "Warning", "Security Audit Logging"),
                                    ("1", "LOG_DELETED", "Warning", "Security Audit Logging")]
    with sqlite3.connect(settings.data_dir / "logs.db") as db:
        assert db.execute("SELECT count(*) FROM audit_outbox").fetchone()[0] == 0


def test_other_services_deliver_audit_events(threat_client, logs_client, settings, auth, threat, forward):
    audit = threat_client.app.state.audit
    audit.settings = replace(settings, audit_post_url="http://logs.test" + BASE,
                             audit_service_token=issue(settings, Role.ADMIN.value, "audit-service"))
    audit.transport = forward(logs_client)
    created = threat_client.post("/AliNaji/threats", json=threat, headers=auth(user_id="3"))
    assert created.status_code == 201
    assert threat_client.get("/AliNaji/threats", headers=auth(Role.USER)).status_code == 403
    assert threat_client.get("/AliNaji/health").json()["pending_audit_events"] == 0
    with sqlite3.connect(settings.data_dir / "threats.db") as db:
        db.execute("DELETE FROM audit_delivery")
    assert audit.flush() == 2
    records = logs_client.get(BASE, headers=auth()).json()
    assert [(r["user_id"], r["action"], r["related_service"]) for r in records] == [
        ("3", "THREAT_CREATED", "Threat Intelligence"), ("local-test-user", "PERMISSION_DENIED", "Threat Intelligence")]
    assert [ActivitySource.model_validate(r).action for r in records] == ["THREAT_CREATED", "PERMISSION_DENIED"]
