from typing import Annotated

from fastapi import Depends, Path, Query, Response

from services.threats.models import ThreatCreate, ThreatRecord, ThreatSearch, ThreatUpdate
from services.threats.repository import ThreatRepository
from shared.app import create_service
from shared.auth import Principal, Role, require
from shared.config import PREFIX, Settings

Id = Annotated[int, Path(gt=0)]


def create_app(settings: Settings | None = None):
    app = create_service("Threat Intelligence", "threats.db", settings or Settings.from_env(), "threats.sql")
    repo = ThreatRepository(app.state.db, app.state.audit)
    readers = require(Role.ADMIN, Role.ANALYST, Role.AUDITOR)
    admin = require(Role.ADMIN)

    @app.post(f"{PREFIX}/threats", response_model=ThreatRecord, status_code=201, tags=["Threats"],
              summary="Add threat indicator (Ali Naji)")
    def create(data: ThreatCreate, user: Principal = Depends(admin)):
        return repo.create(data, user.user_id)

    @app.get(f"{PREFIX}/threats", response_model=list[ThreatRecord], tags=["Threats"],
             summary="Retrieve all threat indicators (Ali Naji)")
    def list_all(user: Principal = Depends(readers)):
        return repo.list()

    @app.get(f"{PREFIX}/threats/search", response_model=list[ThreatRecord], tags=["Threats"],
             summary="Search threat indicators (Ali Naji)")
    def search(filters: Annotated[ThreatSearch, Query()], user: Principal = Depends(require(Role.ADMIN, Role.ANALYST))):
        return repo.list(filters.model_dump(mode="json", exclude_none=True))

    @app.get(f"{PREFIX}/threats/{{threat_id}}", response_model=ThreatRecord, tags=["Threats"],
             summary="Retrieve specific threat indicator (Ali Naji)")
    def get(threat_id: Id, user: Principal = Depends(readers)):
        return repo.get(threat_id)

    @app.put(f"{PREFIX}/threats/{{threat_id}}", response_model=ThreatRecord, tags=["Threats"],
             summary="Update threat information (Ali Naji)")
    def update(threat_id: Id, data: ThreatUpdate, user: Principal = Depends(admin)):
        return repo.update(threat_id, data, user.user_id)

    @app.delete(f"{PREFIX}/threats/{{threat_id}}", status_code=204, tags=["Threats"],
                summary="Delete threat indicator (Ali Naji)")
    def delete(threat_id: Id, user: Principal = Depends(admin)):
        repo.delete(threat_id, user.user_id)
        return Response(status_code=204)

    return app
