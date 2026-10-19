from contextlib import ExitStack
from dataclasses import replace

import httpx
from fastapi.testclient import TestClient

from demo.apps import create_app as owned_app
from demo.dependencies import BASE, create_app
from scripts.dev_tokens import issue
from shared.auth import Role
from shared.upstream import UpstreamClient


def test_fixture_access_and_idempotent_actual_audit_events(settings, auth):
    with TestClient(create_app(settings)) as client:
        health = client.get(BASE + "/health")
        assert health.json()["mode"] == "synthetic-dependencies"
        assert health.headers["X-Lab-Mode"] == "synthetic-dependencies"
        assert client.get(BASE + "/assets").status_code == 401
        assert client.get(BASE + "/assets", headers=auth(Role.USER)).status_code == 403
        assert len(client.get(BASE + "/assets", headers=auth()).json()) == 3
        assert client.get(BASE + "/assets/1", headers=auth()).json()["asset_name"].startswith("DEMO")
        assert client.get(BASE + "/assets/999", headers=auth()).status_code == 404
        assert client.post(BASE + "/users", headers=auth(), json={}).status_code == 405
        events = client.get(BASE + "/logs", headers=auth()).json()
        assert len(events) == 3 and all(e["origin"] == "synthetic_fixture" for e in events)
        body = {"user_id": "test", "action": "THREAT_CREATED", "description": "Actual test request",
                "timestamp": "2026-01-01T00:00:00Z", "severity": "Information", "related_service": "Threat Intelligence"}
        headers = {**auth(), "Idempotency-Key": "test-event"}
        assert client.post(BASE + "/logs", json=body, headers=headers).status_code == 201
        assert client.post(BASE + "/logs", json=body, headers=headers).status_code == 201
        events = client.get(BASE + "/logs", headers=auth()).json()
        assert len(events) == 4
        assert sum(e["origin"] == "actual_demo_api_event" for e in events) == 1
        assert client.post(BASE + "/logs", json=body, headers=auth(Role.ANALYST)).status_code == 403
        assert client.post(BASE + "/logs", json=body, headers=auth()).status_code == 422
    with TestClient(create_app(settings)) as restarted:
        assert len(restarted.get(BASE + "/logs", headers=auth()).json()) == 4


def test_demo_actual_owned_crud_reports_and_audit(settings, auth, vulnerability, threat):
    """Same HTTP adapters and production factories; only external data is synthetic."""
    configured = replace(settings,
        asset_detail_url="http://dependencies/AliNaji/demo/assets/{id}",
        audit_post_url="http://dependencies/AliNaji/demo/logs",
        audit_service_token=issue(settings, Role.ADMIN.value),
        sources={"users": "http://dependencies/AliNaji/demo/users",
                 "assets": "http://dependencies/AliNaji/demo/assets",
                 "incidents": "http://dependencies/AliNaji/demo/incidents",
                 "logs": "http://dependencies/AliNaji/demo/logs",
                 "threats": "http://threats/AliNaji/threats",
                 "vulnerabilities": "http://vulnerabilities/AliNaji/vulnerabilities"})
    clients = {}

    def route(request):
        response = clients[request.url.host].request(request.method, request.url.raw_path.decode(),
                                                   content=request.content, headers=dict(request.headers))
        return httpx.Response(response.status_code, content=response.content,
                              headers={"Content-Type": response.headers.get("Content-Type", "application/json")})

    transport = httpx.MockTransport(route)
    with ExitStack() as stack:
        clients["dependencies"] = stack.enter_context(TestClient(create_app(configured)))
        for service in ["threats", "vulnerabilities", "reports"]:
            app = owned_app(service, configured)
            if service != "threats":
                app.state.upstream = UpstreamClient(transport)
            app.state.audit.transport = transport
            clients[service] = stack.enter_context(TestClient(app))
        result = clients["threats"].post("/AliNaji/threats", headers=auth(), json=threat)
        assert result.status_code == 201 and result.headers["X-Lab-Mode"] == "synthetic-dependencies"
        vulnerability["affected_asset_id"] = 1
        created = clients["vulnerabilities"].post("/AliNaji/vulnerabilities", headers=auth(), json=vulnerability)
        assert created.status_code == 201
        path = f"/AliNaji/vulnerabilities/{created.json()['id']}"
        for status in ["Under Investigation", "In Progress", "Resolved", "Closed"]:
            result = clients["vulnerabilities"].put(path, headers=auth(Role.ANALYST), json={"status": status})
            assert result.status_code == 200 and result.json()["status"] == status
        reports = clients["reports"]
        for kind in ["summary", "assets", "incidents", "threats", "vulnerabilities", "activity"]:
            response = reports.get("/AliNaji/reports/" + kind, headers=auth())
            assert response.status_code == 200, response.text
        summary = reports.get("/AliNaji/reports/summary", headers=auth()).json()
        assert (summary["users"], summary["assets"], summary["incidents"]) == (4, 3, 5)
        assert summary["threats"] == summary["vulnerabilities"] == 1
        activity = reports.get("/AliNaji/reports/activity", headers=auth()).json()
        assert activity["login_attempts"] == 3 and activity["failed_login_attempts"] == 2
        assert activity["total_user_activities"] > 3
        events = clients["dependencies"].get(BASE + "/logs", headers=auth()).json()
        assert any(e["action"] == "VULNERABILITY_CREATED" and e["origin"] == "actual_demo_api_event" for e in events)
        for service in ["threats", "vulnerabilities", "reports"]:
            assert clients[service].get("/AliNaji/health").json()["pending_audit_events"] == 0
