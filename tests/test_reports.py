from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from services.reports.app import create_app
from shared.auth import Role
from shared.upstream import UpstreamClient

BASE = "/AliNaji/reports"
KINDS = ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]


@pytest.fixture
def datasets():
    return {
        "users": [{"id": 1}, {"id": 2}],
        "assets": [{"id": 7, "asset_type": "Server", "criticality_level": "Critical"},
                   {"id": 8, "asset_type": "Workstation", "criticality_level": "Low"}],
        "incidents": [{"id": 1, "severity": "High", "status": "Open"},
                      {"id": 2, "severity": "Critical", "status": "Under Investigation"},
                      {"id": 3, "severity": "High", "status": "Resolved"}],
        "threats": [{"id": 1, "threat_type": "Domain", "threat_value": "lab.example.com", "description": "Fixture",
                     "severity": "Critical", "source": "Fixture", "date_added": "2026-01-01T00:00:00Z"},
                    {"id": 2, "threat_type": "IP Address", "threat_value": "192.0.2.1", "description": "Fixture",
                     "severity": "High", "source": "Fixture", "date_added": "2026-01-02T00:00:00Z"}],
        "vulnerabilities": [{"id": 1, "severity": "High", "status": "Open"},
                            {"id": 2, "severity": "Critical", "status": "Resolved"}],
        "logs": [{"id": i, "action": action, "description": "Fixture", "timestamp": f"2026-01-0{i}T00:00:00Z",
                  "severity": "Information", "related_service": "Test"} for i, action in enumerate([
                      "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_FAILED", "THREAT_CREATED", "AUTHENTICATION_FAILED"], 1)],
    }


@pytest.fixture
def reports_client(settings, datasets):
    configured = replace(settings, sources={name: f"http://test/{name}" for name in datasets})
    app = create_app(configured)

    def respond(request):
        assert request.headers["Authorization"].startswith("Bearer ")
        return httpx.Response(200, json=datasets[request.url.path.lstrip("/")])

    app.state.upstream = UpstreamClient(httpx.MockTransport(respond))
    with TestClient(app) as client:
        yield client


def test_all_six_report_totals(reports_client, auth):
    c = reports_client
    summary = c.get(BASE + "/summary", headers=auth()).json()
    assert summary["users"] == 2 and summary["assets"] == 2 and summary["incidents"] == 3
    assert summary["open_incidents"] == 1 and summary["unresolved_incidents"] == 2
    assert summary["threats"] == 2 and summary["critical_threats"] == 1
    assert summary["vulnerabilities"] == 2 and summary["critical_vulnerabilities"] == 1
    assert len(summary["sources"]) == 6 and summary["generated_at"]
    incidents = c.get(BASE + "/incidents", headers=auth()).json()
    assert incidents["total_incidents"] == 3
    assert incidents["incidents_by_severity"] == {"Low": 0, "Medium": 0, "High": 2, "Critical": 1}
    assert incidents["incidents_by_status"]["Under Investigation"] == 1
    assets = c.get(BASE + "/assets", headers=auth()).json()
    assert assets["total_assets"] == 2 and assets["critical_assets"] == 1
    assert assets["assets_by_type"] == {"Server": 1, "Workstation": 1}
    threats = c.get(BASE + "/threats", headers=auth()).json()
    assert threats["total_threats"] == sum(threats["threats_by_severity"].values()) == sum(threats["threats_by_type"].values()) == 2
    assert [r["id"] for r in threats["recent_added_threats"]] == [2, 1]
    vulns = c.get(BASE + "/vulnerabilities", headers=auth()).json()
    assert vulns["total_vulnerabilities"] == sum(vulns["vulnerabilities_by_status"].values()) == 2
    assert vulns["critical_vulnerabilities"] == 1 and vulns["vulnerabilities_by_status"]["Resolved"] == 1
    activity = c.get(BASE + "/activity", headers=auth()).json()
    assert activity["total_user_activities"] == 5
    assert activity["login_attempts"] == 3 and activity["failed_login_attempts"] == 2
    assert activity["most_performed_actions"][0] == {"action": "LOGIN_FAILED", "count": 2}
    assert activity["recent_security_activities"][0]["id"] == 5


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("role,status", [(Role.ADMIN, 200), (Role.AUDITOR, 200), (Role.ANALYST, 403), (Role.USER, 403)])
def test_report_roles(reports_client, auth, kind, role, status):
    assert reports_client.get(f"{BASE}/{kind}", headers=auth(role)).status_code == status


@pytest.mark.parametrize("kind", KINDS)
def test_empty_datasets_are_valid_zero_reports(reports_client, auth, datasets, kind):
    for name in datasets:
        datasets[name] = []
    response = reports_client.get(f"{BASE}/{kind}", headers=auth())
    assert response.status_code == 200
    assert all(value == 0 for key, value in response.json().items() if isinstance(value, int))


@pytest.mark.parametrize("payload", [{"data": [], "total": 5}, {"data": [], "next": "page2"},
    {"data": [], "has_more": True}, {"data": [], "pagination": {"pages": 2}},
    {"data": [], "total_pages": 2}, {"unexpected": []}, "wrong", [{"id": 1}],
    [{"id": True, "asset_type": "Server", "criticality_level": "High"}],
    [{"id": 1, "asset_type": "Server", "criticality_level": "High"}] * 2])
def test_rejects_malformed_or_partial_upstream(reports_client, auth, payload):
    reports_client.app.state.upstream = UpstreamClient(httpx.MockTransport(lambda req: httpx.Response(200, json=payload)))
    response = reports_client.get(BASE + "/assets", headers=auth())
    assert response.status_code == 503 and response.json()["status"] == "error"


def test_dependency_failure_and_bearer(reports_client, auth):
    c = reports_client
    assert c.get(BASE + "/summary").status_code == 401
    for status in [401, 403, 404, 500, 503]:
        c.app.state.upstream = UpstreamClient(httpx.MockTransport(lambda req: httpx.Response(status)))
        assert c.get(BASE + "/assets", headers=auth()).status_code == 503
    def timeout(req):
        raise httpx.ReadTimeout("test timeout")
    c.app.state.upstream = UpstreamClient(httpx.MockTransport(timeout))
    assert c.get(BASE + "/assets", headers=auth()).status_code == 503


def test_wrapped_records_and_recent_limit(reports_client, auth, datasets):
    c = reports_client
    datasets["threats"] = [{**datasets["threats"][0], "id": i, "date_added": f"2026-01-{i:02d}T00:00:00Z"} for i in range(1, 16)]
    c.app.state.upstream = UpstreamClient(httpx.MockTransport(lambda req: httpx.Response(200, json={
        "data": datasets[req.url.path.lstrip("/")], "total": len(datasets[req.url.path.lstrip("/")])})))
    body = c.get(BASE + "/threats", headers=auth()).json()
    assert body["total_threats"] == 15
    assert len(body["recent_added_threats"]) == 10 and body["recent_added_threats"][0]["id"] == 15


def test_missing_configuration_returns_503(settings, auth):
    with TestClient(create_app(settings)) as c:
        response = c.get(BASE + "/summary", headers=auth())
        assert response.status_code == 503 and "not configured" in response.json()["message"]


def test_every_route_contains_full_student_name(reports_client, threat_client, vulnerability_client):
    for client in [reports_client, threat_client, vulnerability_client]:
        assert all(route.path.startswith("/AliNaji/") for route in client.app.routes)
