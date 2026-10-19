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
