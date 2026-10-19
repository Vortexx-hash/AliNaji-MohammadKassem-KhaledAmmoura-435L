from dataclasses import replace

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from scripts.dev_tokens import issue
from services.threats.app import create_app
from shared.audit import AuditOutbox
from shared.auth import Role


def test_wrong_signature_issuer_audience_or_missing_claims(threat_client, settings):
    valid = jwt.decode(issue(settings, Role.ADMIN.value), settings.jwt_secret, algorithms=["HS256"],
                       audience=settings.jwt_audience, issuer=settings.jwt_issuer)
    cases = [(settings.jwt_secret + "wrong", valid),
             (settings.jwt_secret, {**valid, "iss": "wrong"}),
             (settings.jwt_secret, {**valid, "aud": "wrong"}),
             (settings.jwt_secret, {**valid, "exp": str(valid["exp"])}),
             (settings.jwt_secret, {**valid, "role": "Admin"})]
    for claim in ["exp", "iat", "sub", "role", "account_status"]:
        cases.append((settings.jwt_secret, {k: v for k, v in valid.items() if k != claim}))
    for key, claims in cases:
        token = jwt.encode(claims, key, algorithm="HS256")
        assert threat_client.get("/AliNaji/threats", headers={"Authorization": "Bearer " + token}).status_code == 401


@pytest.mark.parametrize("payload,status", [
    ({"id": "local-test-user", "role": "Security Administrator", "account_status": "Active"}, 200),
    ({"id": "local-test-user", "role": "Auditor", "account_status": "Active"}, 401),
    ({"id": "local-test-user", "role": "Security Administrator", "account_status": "Suspended"}, 401),
    ({"id": "different", "role": "Security Administrator", "account_status": "Active"}, 401),
    ({"unexpected": 1}, 503), ([], 503),
])
def test_identity_status_check(settings, auth, monkeypatch, payload, status):
    configured = replace(settings, identity_me_url="http://identity.test/me")
    monkeypatch.setattr("shared.auth.httpx.get", lambda *a, **kw: httpx.Response(200, json=payload, request=httpx.Request("GET", a[0])))
    with TestClient(create_app(configured)) as c:
        assert c.get("/AliNaji/threats", headers=auth()).status_code == status


def test_audit_outage_preserves_change_and_retry(threat_client, settings, auth, threat):
    c = threat_client
    configured = replace(settings, audit_post_url="http://logs.test/logs", audit_service_token="test-service-token")
    calls = []
    def unavailable(request):
        calls.append(request)
        return httpx.Response(503)
    audit = AuditOutbox(c.app.state.db, configured, "Threat Intelligence", httpx.MockTransport(unavailable))
    # Repository and app share this object; update its configuration and transport.
    c.app.state.audit.settings = configured
    c.app.state.audit.transport = httpx.MockTransport(unavailable)
    assert c.post("/AliNaji/threats", json=threat, headers=auth()).status_code == 201
    assert len(c.get("/AliNaji/threats", headers=auth()).json()) == 1
    assert c.get("/AliNaji/health").json()["pending_audit_events"] == 1
    assert len(calls) == 1
    seen = []
    def available(request):
        assert request.headers["Authorization"] == "Bearer test-service-token"
        assert request.headers["Idempotency-Key"]
        seen.append(request.headers["Idempotency-Key"])
        return httpx.Response(201)
    audit.transport = httpx.MockTransport(available)
    assert audit.flush() == 1
    assert audit.flush() == 0
    assert len(seen) == 1 and c.get("/AliNaji/health").json()["pending_audit_events"] == 0


def test_permission_denials_are_recorded(threat_client, auth, settings):
    assert threat_client.delete("/AliNaji/threats/123", headers=auth(Role.ANALYST)).status_code == 403
    with threat_client.app.state.db.connect() as conn:
        event = dict(conn.execute("SELECT * FROM audit_outbox").fetchone())
    assert event["action"] == "PERMISSION_DENIED" and event["severity"] == "Warning"
    assert "Bearer" not in event["description"]
