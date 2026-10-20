import pytest
from fastapi.testclient import TestClient

from scripts.dev_tokens import issue
from shared.auth import Role
from shared.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(jwt_secret="test-secret-only-" * 4, data_dir=tmp_path)


@pytest.fixture
def auth(settings):
    def headers(role=Role.ADMIN, **kwargs):
        return {"Authorization": "Bearer " + issue(settings, role.value, **kwargs)}
    return headers


@pytest.fixture
def threat_client(settings):
    from services.threats.app import create_app
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def threat():
    return {"threat_type": "IP Address", "threat_value": "203.0.113.8",
            "description": "Lab indicator for a suspected scanning host", "severity": "High", "source": "Lab sensor"}


@pytest.fixture
def vulnerability():
    return {"title": "Lab web service weakness", "description": "A locally discovered lab issue",
            "cve_identifier": "CVE-2025-12345", "cvss_score": 8.1, "severity": "High",
            "affected_asset_id": 7, "discovery_source": "Lab scanner"}


@pytest.fixture
def vulnerability_client(settings):
    from dataclasses import replace
    import httpx
    from services.vulnerabilities.app import create_app
    from shared.upstream import UpstreamClient

    configured = replace(settings, asset_detail_url="http://assets.test/Teammate/assets/{id}")
    app = create_app(configured)

    def external_asset(request):
        assert request.headers.get("Authorization", "").startswith("Bearer ")
        if request.url.path.endswith("/7"):
            return httpx.Response(200, json={"id": 7, "asset_name": "Test fixture asset"})
        return httpx.Response(404, json={"status": "error"})

    app.state.upstream = UpstreamClient(httpx.MockTransport(external_asset))
    with TestClient(app) as client:
        yield client


@pytest.fixture
def users_client(settings, monkeypatch):
    from services.users.app import create_app
    monkeypatch.setattr("services.users.security.ROUNDS", 4)
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def new_user():
    return {"full_name": "Lab Employee", "username": "lab_employee", "email": "employee@example.com",
            "password": "Lab#Pass2026", "department": "Finance", "role": "Regular Employee/User"}


@pytest.fixture
def logs_client(settings):
    from services.logs.app import create_app
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def notifications_client(settings):
    from dataclasses import replace
    import httpx
    from services.notifications.app import create_app
    from shared.upstream import UpstreamClient

    app = create_app(replace(settings, sources={"users": "http://users.test/MohamedKassem/users"}))

    def users_api(request):
        assert request.headers.get("Authorization", "").startswith("Bearer ")
        return httpx.Response(200, json=[{"id": 5, "username": "lab_employee"}, {"id": 6, "username": "lab_analyst"}])

    app.state.upstream = UpstreamClient(httpx.MockTransport(users_api))
    with TestClient(app) as client:
        yield client


@pytest.fixture
def forward():
    """Route an httpx call made by one service into another service's TestClient."""
    import httpx

    def to(client):
        def handler(request):
            response = client.request(request.method, request.url.path, params=request.url.params,
                                      headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
                                      content=request.content)
            return httpx.Response(response.status_code, content=response.content, headers=response.headers)
        return httpx.MockTransport(handler)
    return to
