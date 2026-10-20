import json
import sqlite3
from dataclasses import replace

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from shared.auth import Role
from shared.upstream import UpstreamClient

BASE = "/MohamedKassem/users"
PASSWORD = "Lab#Pass2026"


def register(client, body, headers=None):
    return client.post(BASE + "/register", json=body, headers=headers or {})


def login(client, password=PASSWORD, **identifier):
    return client.post(BASE + "/login", json={**identifier, "password": password})


def audit_rows(settings):
    with sqlite3.connect(settings.data_dir / "users.db") as db:
        return db.execute("SELECT user_id, action, severity FROM audit_outbox ORDER BY rowid").fetchall()


def test_register_stores_hash_and_never_returns_it(users_client, new_user, settings):
    response = register(users_client, new_user)
    assert response.status_code == 201
    user = response.json()
    assert user["id"] > 0 and user["account_status"] == "Active" and user["last_login_date"] is None
    assert "password" not in user and "password_hash" not in user
    with sqlite3.connect(settings.data_dir / "users.db") as db:
        stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$2b$") and PASSWORD not in stored
    assert audit_rows(settings) == [("1", "USER_CREATED", "Information")]


def test_duplicate_username_and_email(users_client, new_user):
    assert register(users_client, new_user).status_code == 201
    response = register(users_client, {**new_user, "username": "LAB_EMPLOYEE", "email": "other@example.com"})
    assert response.status_code == 409 and response.json()["message"] == "Username already exists"
    response = register(users_client, {**new_user, "username": "other_user", "email": "Employee@Example.com"})
    assert response.status_code == 409 and response.json()["message"] == "Email is already registered"


@pytest.mark.parametrize("change", [
    {"email": "not-an-email"}, {"email": "user@localhost"}, {"username": "ab"}, {"username": "bad name"},
    {"password": "Sh0rt!"}, {"password": "lowercase1!"}, {"password": "UPPERCASE1!"}, {"password": "NoDigits!!"},
    {"password": "NoSymbol123"}, {"password": "Aa1!" + "x" * 70}, {"role": "Admin"}, {"full_name": " "},
    {"department": None}, {"unexpected": True},
])
def test_rejects_invalid_registration(users_client, new_user, change):
    response = register(users_client, {**new_user, **change})
    assert response.status_code == 422 and response.json()["status"] == "error"


def test_missing_fields_are_all_reported(users_client):
    response = register(users_client, {})
    fields = {error["field"] for error in response.json()["errors"]}
    assert response.status_code == 422
    assert fields == {f"body.{name}" for name in ("full_name", "username", "email", "password", "department", "role")}


def test_registration_role_rules(users_client, new_user, auth, settings):
    analyst = {**new_user, "username": "analyst_one", "email": "analyst@example.com", "role": "Security Analyst"}
    assert register(users_client, analyst).status_code == 403
    assert register(users_client, analyst, auth(Role.USER)).status_code == 403
    assert register(users_client, analyst, auth(Role.ANALYST)).status_code == 403
    assert register(users_client, new_user, auth(Role.AUDITOR)).status_code == 403
    assert register(users_client, new_user, {"Authorization": "Bearer invalid"}).status_code == 401
    assert register(users_client, analyst, auth(Role.ADMIN)).json()["role"] == "Security Analyst"
    assert register(users_client, new_user, auth(Role.USER)).status_code == 201
    actions = [action for _, action, _ in audit_rows(settings)]
    assert actions.count("PERMISSION_DENIED") == 4 and actions.count("USER_CREATED") == 2


def test_login_success_failure_and_audit(users_client, new_user, settings):
    user_id = register(users_client, new_user).json()["id"]
    response = login(users_client, username="Lab_Employee")
    assert response.status_code == 200
    body = response.json()
    assert body["message"] == "Login successful" and body["token_type"] == "bearer" and body["expires_in"] == 3600
    assert body["user"]["last_login_date"] and "password_hash" not in body["user"]
    claims = jwt.decode(body["access_token"], settings.jwt_secret, algorithms=["HS256"],
                        audience=settings.jwt_audience, issuer=settings.jwt_issuer)
    assert claims["sub"] == str(user_id) and claims["role"] == new_user["role"] and claims["account_status"] == "Active"
    assert login(users_client, email="EMPLOYEE@example.com").status_code == 200
    for response in [login(users_client, "Wrong#Pass1", username="lab_employee"),
                     login(users_client, username="nobody")]:
        assert response.status_code == 401 and response.json()["message"] == "Invalid username/email or password"
    assert users_client.post(BASE + "/login", json={"username": "a", "email": "a@b.co", "password": "x"}).status_code == 422
    assert users_client.post(BASE + "/login", json={"password": "x"}).status_code == 422
    assert audit_rows(settings)[1:] == [("1", "LOGIN_SUCCESS", "Information"), ("1", "LOGIN_SUCCESS", "Information"),
                                         ("1", "LOGIN_FAILED", "Warning"), (None, "LOGIN_FAILED", "Warning")]


def test_login_token_is_accepted_by_other_services(users_client, threat_client, new_user, auth):
    auditor = {**new_user, "username": "auditor_one", "email": "auditor@example.com", "role": "Auditor"}
    assert register(users_client, auditor, auth(Role.ADMIN)).status_code == 201
    assert register(users_client, new_user).status_code == 201
    auditor_token = login(users_client, username="auditor_one").json()["access_token"]
    user_token = login(users_client, username="lab_employee").json()["access_token"]
    assert threat_client.get("/AliNaji/threats", headers={"Authorization": f"Bearer {auditor_token}"}).status_code == 200
    assert threat_client.get("/AliNaji/threats", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403


@pytest.mark.parametrize("status", ["Suspended", "Inactive"])
def test_inactive_or_suspended_accounts_cannot_log_in(users_client, new_user, auth, settings, status):
    user_id = register(users_client, new_user).json()["id"]
    assert users_client.put(f"{BASE}/{user_id}", json={"account_status": status}, headers=auth()).status_code == 200
    response = login(users_client, username="lab_employee")
    assert response.status_code == 403 and status.lower() in response.json()["message"]
    assert login(users_client, "Wrong#Pass1", username="lab_employee").status_code == 401
    assert audit_rows(settings)[-1] == ("1", "LOGIN_FAILED", "Warning")
    users_client.put(f"{BASE}/{user_id}", json={"account_status": "Active"}, headers=auth())
    assert login(users_client, username="lab_employee").status_code == 200


def test_read_permissions(users_client, new_user, auth):
    register(users_client, new_user)
    for role, status in [(Role.ADMIN, 200), (Role.AUDITOR, 200), (Role.ANALYST, 403), (Role.USER, 403)]:
        assert users_client.get(BASE, headers=auth(role)).status_code == status
    assert users_client.get(BASE).status_code == 401
    listed = users_client.get(BASE, headers=auth()).json()
    assert [user["username"] for user in listed] == ["lab_employee"] and "password_hash" not in listed[0]
    profile = BASE + "/lab_employee"
    for role, user_id, status in [(Role.ADMIN, "9", 200), (Role.AUDITOR, "9", 200), (Role.USER, "1", 200),
                                  (Role.USER, "2", 403), (Role.ANALYST, "1", 403)]:
        assert users_client.get(profile, headers=auth(role, user_id=user_id)).status_code == status
    assert users_client.get(BASE + "/missing_user", headers=auth()).status_code == 404
    assert users_client.get(BASE + "/missing_user", headers=auth(Role.USER, user_id="1")).status_code == 403


def test_update_rules(users_client, new_user, auth, settings):
    user_id = register(users_client, new_user).json()["id"]
    register(users_client, {**new_user, "username": "second_user", "email": "second@example.com"})
    own = auth(Role.USER, user_id=str(user_id))
    response = users_client.put(f"{BASE}/{user_id}", headers=own,
                                json={"full_name": "Lab Employee Two", "email": "New@Example.com", "department": "SOC"})
    updated = response.json()
    assert response.status_code == 200
    assert (updated["full_name"], updated["email"], updated["department"]) == ("Lab Employee Two", "new@example.com", "SOC")
    for body in [{"role": "Security Administrator"}, {"account_status": "Active"}]:
        assert users_client.put(f"{BASE}/{user_id}", json=body, headers=own).status_code == 403
    assert users_client.put(f"{BASE}/2", json={"department": "IT"}, headers=own).status_code == 403
    for role in (Role.ANALYST, Role.AUDITOR):
        assert users_client.put(f"{BASE}/{user_id}", json={"department": "IT"}, headers=auth(role)).status_code == 403
    for body, status in [({}, 422), ({"department": None}, 422), ({"password": "New#Pass2026"}, 422),
                         ({"email": "second@example.com"}, 409)]:
        assert users_client.put(f"{BASE}/{user_id}", json=body, headers=auth()).status_code == status
    assert users_client.put(f"{BASE}/2147483647", json={"department": "IT"}, headers=auth()).status_code == 404
    response = users_client.put(f"{BASE}/{user_id}", json={"role": "Security Analyst"}, headers=auth())
    assert response.status_code == 200 and response.json()["role"] == "Security Analyst"
    assert audit_rows(settings)[-2:] == [("local-test-user", "USER_UPDATED", "Information"),
                                         ("local-test-user", "ROLE_CHANGED", "Information")]


def test_delete_user(users_client, new_user, auth, settings):
    user_id = register(users_client, new_user).json()["id"]
    for role in (Role.ANALYST, Role.AUDITOR, Role.USER):
        assert users_client.delete(f"{BASE}/{user_id}", headers=auth(role)).status_code == 403
    assert users_client.delete(f"{BASE}/{user_id}", headers=auth()).status_code == 204
    assert users_client.get(BASE + "/lab_employee", headers=auth()).status_code == 404
    assert users_client.delete(f"{BASE}/{user_id}", headers=auth()).status_code == 404
    assert audit_rows(settings)[-1] == ("local-test-user", "USER_DELETED", "Warning")


def test_role_and_status_changes_notify_the_user(settings, auth, new_user, monkeypatch):
    from services.users.app import create_app
    monkeypatch.setattr("services.users.security.ROUNDS", 4)
    sent = []

    def notifications_api(request):
        sent.append(request)
        return httpx.Response(201 if len(sent) == 1 else 503)

    app = create_app(replace(settings, notification_post_url="http://notifications.test/MohamedKassem/notifications"))
    app.state.upstream = UpstreamClient(httpx.MockTransport(notifications_api))
    with TestClient(app) as c:
        user_id = register(c, new_user).json()["id"]
        assert c.put(f"{BASE}/{user_id}", json={"department": "IT"}, headers=auth()).status_code == 200
        assert not sent
        response = c.put(f"{BASE}/{user_id}", json={"role": "Auditor", "account_status": "Suspended"}, headers=auth())
        assert response.status_code == 200
    payloads = [json.loads(request.content) for request in sent]
    assert [p["title"] for p in payloads] == ["Your role was changed", "Your account status was changed"]
    assert all(p["user_id"] == user_id and p["notification_type"] == "System Notification" for p in payloads)
