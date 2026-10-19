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
