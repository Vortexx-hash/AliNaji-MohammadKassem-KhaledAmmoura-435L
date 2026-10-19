from typing import Annotated

from fastapi import Depends, Path, Query, Response

from services.vulnerabilities.models import VulnerabilityCreate, VulnerabilityRecord, VulnerabilitySearch, VulnerabilityUpdate
from services.vulnerabilities.repository import VulnerabilityRepository
from shared.app import create_service
from shared.auth import Principal, Role, require
from shared.config import PREFIX, Settings
from shared.upstream import UpstreamClient

Id = Annotated[int, Path(gt=0)]


def create_app(settings: Settings | None = None):
    app = create_service("Vulnerability Management", "vulnerabilities.db", settings or Settings.from_env(), "vulnerabilities.sql")
    repo = VulnerabilityRepository(app.state.db, app.state.audit)
    app.state.upstream = UpstreamClient()
    readers = require(Role.ADMIN, Role.ANALYST, Role.AUDITOR)
    admin = require(Role.ADMIN)

    @app.post(f"{PREFIX}/vulnerabilities", response_model=VulnerabilityRecord, status_code=201,
              tags=["Vulnerabilities"], summary="Add new vulnerability (Ali Naji)")
    def create(data: VulnerabilityCreate, user: Principal = Depends(admin)):
        asset = app.state.upstream.asset(app.state.settings.asset_detail_url, data.affected_asset_id, user.token)
        return repo.create(data, asset, user.user_id)

    @app.get(f"{PREFIX}/vulnerabilities", response_model=list[VulnerabilityRecord],
             tags=["Vulnerabilities"], summary="Retrieve all vulnerabilities (Ali Naji)")
    def list_all(user: Principal = Depends(readers)):
        return repo.list()

    @app.get(f"{PREFIX}/vulnerabilities/search", response_model=list[VulnerabilityRecord],
             tags=["Vulnerabilities"], summary="Search vulnerabilities (Ali Naji)")
    def search(filters: Annotated[VulnerabilitySearch, Query()], user: Principal = Depends(readers)):
        return repo.list(filters.model_dump(mode="json", exclude_none=True))

    @app.get(f"{PREFIX}/vulnerabilities/{{vulnerability_id}}", response_model=VulnerabilityRecord,
             tags=["Vulnerabilities"], summary="Retrieve specific vulnerability (Ali Naji)")
    def get(vulnerability_id: Id, user: Principal = Depends(readers)):
        return repo.get(vulnerability_id)

    @app.put(f"{PREFIX}/vulnerabilities/{{vulnerability_id}}", response_model=VulnerabilityRecord,
             tags=["Vulnerabilities"], summary="Update vulnerability information (Ali Naji)")
    def update(vulnerability_id: Id, data: VulnerabilityUpdate,
               user: Principal = Depends(require(Role.ADMIN, Role.ANALYST))):
        return repo.update(vulnerability_id, data, user.user_id)

    @app.delete(f"{PREFIX}/vulnerabilities/{{vulnerability_id}}", status_code=204,
                tags=["Vulnerabilities"], summary="Delete vulnerability (Ali Naji)")
    def delete(vulnerability_id: Id, user: Principal = Depends(admin)):
        repo.delete(vulnerability_id, user.user_id)
        return Response(status_code=204)

    return app
