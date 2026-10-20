import sqlite3
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from shared.auth import Role
from shared.upstream import UpstreamClient

BASE = "/MohamedKassem/notifications"


@pytest.fixture
def note():
    return {"user_id": 5, "title": "Suspicious login detected", "message": "A login from a new location was blocked",
            "notification_type": "Security Alert", "severity": "High"}


def create(client, auth, body):
    response = client.post(BASE, json=body, headers=auth())
    assert response.status_code == 201
    return response.json()


def test_create_verifies_recipient_and_keeps_foreign_key(notifications_client, auth, note, settings):
    item = create(notifications_client, auth, note)
    assert {k: item[k] for k in note} == note
    assert item["status"] == "Unread" and item["read_date"] is None and item["creation_date"]
    with sqlite3.connect(settings.data_dir / "notifications.db") as db:
        db.execute("PRAGMA foreign_keys = ON")
        assert db.execute("SELECT user_id, username FROM user_references").fetchall() == [(5, "lab_employee")]
        assert db.execute("SELECT action FROM audit_outbox").fetchall() == [("NOTIFICATION_CREATED",)]
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO notifications (user_id,title,message,notification_type,severity,creation_date) "
                       "VALUES (99,'t','m','Security Alert','Low','2026-01-01T00:00:00+00:00')")
    response = notifications_client.post(BASE, json={**note, "user_id": 99}, headers=auth())
    assert response.status_code == 404 and response.json()["message"] == "Recipient user not found"


@pytest.mark.parametrize("users_response", [httpx.Response(503), httpx.Response(200, json={"id": 5}),
                                            httpx.Response(200, content=b"not json")])
def test_users_service_failures_return_503(notifications_client, auth, note, users_response):
    notifications_client.app.state.upstream = UpstreamClient(httpx.MockTransport(lambda request: users_response))
    assert notifications_client.post(BASE, json=note, headers=auth()).status_code == 503


@pytest.mark.parametrize("change", [
    {"notification_type": "Alert"}, {"severity": "Severe"}, {"user_id": 0}, {"user_id": "5"}, {"title": " "},
    {"message": None}, {"status": "Read"}, {"unexpected": 1},
])
def test_rejects_invalid_notifications(notifications_client, auth, note, change):
    response = notifications_client.post(BASE, json={**note, **change}, headers=auth())
    assert response.status_code == 422 and response.json()["status"] == "error"


def test_user_notifications_and_empty_results(notifications_client, auth, note):
    first = create(notifications_client, auth, note)
    second = create(notifications_client, auth, {**note, "notification_type": "System Notification", "severity": "Low"})
    response = notifications_client.get(BASE + "/user/5", headers=auth())
    assert response.status_code == 200 and response.json() == [first, second]
    response = notifications_client.get(BASE + "/user/6", headers=auth())
    assert response.status_code == 200 and response.json() == []
    assert notifications_client.get(f"{BASE}/{first['id']}", headers=auth()).json() == first
    assert notifications_client.get(f"{BASE}/2147483647", headers=auth()).status_code == 404


def test_mark_as_read_once(notifications_client, auth, note, settings):
    item = create(notifications_client, auth, note)
    own = auth(Role.USER, user_id="5")
    first = notifications_client.put(f"{BASE}/{item['id']}/read", headers=own)
    assert first.status_code == 200 and first.json()["status"] == "Read" and first.json()["read_date"]
    again = notifications_client.put(f"{BASE}/{item['id']}/read", headers=own)
    assert again.status_code == 200 and again.json() == first.json()
    assert notifications_client.put(f"{BASE}/2147483647/read", headers=auth()).status_code == 404
    with sqlite3.connect(settings.data_dir / "notifications.db") as db:
        assert db.execute("SELECT status, read_date FROM notifications").fetchone() == ("Read", first.json()["read_date"])
        assert [r[0] for r in db.execute("SELECT action FROM audit_outbox")] == ["NOTIFICATION_CREATED", "NOTIFICATION_READ"]
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE notifications SET status='Unread', read_date=NULL")


def test_search(notifications_client, auth, note):
    ids = [create(notifications_client, auth, body)["id"] for body in [
        note, {**note, "user_id": 6, "notification_type": "Incident Assignment", "severity": "Medium"},
        {**note, "severity": "Critical", "notification_type": "Threat Alert"}]]
    notifications_client.put(f"{BASE}/{ids[2]}/read", headers=auth())

    def search(headers=None, **params):
        response = notifications_client.get(BASE + "/search", params=params, headers=headers or auth())
        assert response.status_code == 200
        return [row["id"] for row in response.json()]

    assert search(user_id=5) == [ids[0], ids[2]]
    assert search(notification_type="Incident Assignment") == [ids[1]]
    assert search(severity="Critical") == [ids[2]]
    assert search(status="Unread") == [ids[0], ids[1]]
    assert search(user_id=5, status="Read", severity="Critical") == [ids[2]]
    assert search(notification_type="Vulnerability Alert") == []
    assert search(auth(Role.AUDITOR)) == ids
    assert search(auth(Role.ANALYST, user_id="6")) == [ids[1]]
    for params in [{"status": "Seen"}, {"severity": "Severe"}, {"user_id": "abc"}, {"unknown": 1}]:
        assert notifications_client.get(BASE + "/search", params=params, headers=auth()).status_code == 422


def test_role_scoping(notifications_client, auth, note, settings):
    employee_note = create(notifications_client, auth, note)["id"]
    analyst_note = create(notifications_client, auth, {**note, "user_id": 6})["id"]
    employee, analyst = auth(Role.USER, user_id="5"), auth(Role.ANALYST, user_id="6")
    c = notifications_client
    for headers, own_user, own_note, other_user, other_note in [
            (employee, 5, employee_note, 6, analyst_note), (analyst, 6, analyst_note, 5, employee_note)]:
        assert c.get(f"{BASE}/user/{own_user}", headers=headers).status_code == 200
        assert c.get(f"{BASE}/user/{other_user}", headers=headers).status_code == 403
        assert c.get(f"{BASE}/{own_note}", headers=headers).status_code == 200
        assert c.get(f"{BASE}/{other_note}", headers=headers).status_code == 403
        assert c.put(f"{BASE}/{other_note}/read", headers=headers).status_code == 403
        assert c.post(BASE, json=note, headers=headers).status_code == 403
        assert c.delete(f"{BASE}/{own_note}", headers=headers).status_code == 403
    assert c.get(BASE + "/search", headers=employee).status_code == 403
    assert c.get(BASE + "/search", params={"user_id": 5}, headers=analyst).status_code == 403
    auditor = auth(Role.AUDITOR)
    assert c.get(f"{BASE}/user/5", headers=auditor).status_code == 200
    assert c.get(f"{BASE}/{employee_note}", headers=auditor).status_code == 200
    assert c.put(f"{BASE}/{employee_note}/read", headers=auditor).status_code == 403
    assert c.post(BASE, json=note, headers=auditor).status_code == 403
    assert c.delete(f"{BASE}/{employee_note}", headers=auditor).status_code == 403
    assert c.get(f"{BASE}/user/5").status_code == 401
    with sqlite3.connect(settings.data_dir / "notifications.db") as db:
        denied = db.execute("SELECT count(*) FROM audit_outbox WHERE action='PERMISSION_DENIED'").fetchone()[0]
    assert denied == 15


def test_delete(notifications_client, auth, note, settings):
    item = create(notifications_client, auth, note)
    assert notifications_client.delete(f"{BASE}/{item['id']}", headers=auth()).status_code == 204
    assert notifications_client.get(f"{BASE}/{item['id']}", headers=auth()).status_code == 404
    assert notifications_client.delete(f"{BASE}/{item['id']}", headers=auth()).status_code == 404
    with sqlite3.connect(settings.data_dir / "notifications.db") as db:
        assert db.execute("SELECT action FROM audit_outbox ORDER BY rowid DESC").fetchone() == ("NOTIFICATION_DELETED",)


def test_role_change_creates_notification_through_both_services(settings, auth, new_user, forward, monkeypatch):
    from services.notifications.app import create_app as notifications_app
    from services.users.app import create_app as users_app
    monkeypatch.setattr("services.users.security.ROUNDS", 4)
    users = users_app(replace(settings, notification_post_url="http://notifications.test" + BASE))
    notifications = notifications_app(replace(settings, sources={"users": "http://users.test/MohamedKassem/users"}))
    with TestClient(users) as u, TestClient(notifications) as n:
        users.state.upstream = UpstreamClient(forward(n))
        notifications.state.upstream = UpstreamClient(forward(u))
        user_id = u.post("/MohamedKassem/users/register", json=new_user).json()["id"]
        assert u.put(f"/MohamedKassem/users/{user_id}", json={"role": "Security Analyst"}, headers=auth()).status_code == 200
        token = u.post("/MohamedKassem/users/login", json={"username": "lab_employee", "password": "Lab#Pass2026"}).json()["access_token"]
        inbox = n.get(f"{BASE}/user/{user_id}", headers={"Authorization": f"Bearer {token}"}).json()
    assert [(i["title"], i["notification_type"], i["status"]) for i in inbox] == [
        ("Your role was changed", "System Notification", "Unread")]
