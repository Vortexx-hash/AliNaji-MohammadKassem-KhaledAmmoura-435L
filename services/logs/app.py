from typing import Annotated

from fastapi import Depends, Header, Path, Query, Response

from services.logs.models import LogCreate, LogRecord, LogSearch
from services.logs.repository import LogRepository, LogWriter
from shared.app import create_service
from shared.auth import Principal, Role, require
from shared.config import Settings

PREFIX = "/MohamedKassem"
AUTHOR = "Mohamed Kassem"
SERVICE = "Security Audit Logging"
Id = Annotated[int, Path(gt=0)]


def create_app(settings: Settings | None = None):
    app = create_service(SERVICE, "logs.db", settings or Settings.from_env(), "logs.sql", PREFIX, AUTHOR)
    app.state.audit = LogWriter(app.state.db, app.state.settings, SERVICE)
    repo = LogRepository(app.state.db, app.state.audit)
    admin = require(Role.ADMIN)
    oversight = require(Role.ADMIN, Role.AUDITOR)
    investigators = require(Role.ADMIN, Role.AUDITOR, Role.ANALYST)

    @app.post(f"{PREFIX}/logs", response_model=LogRecord, status_code=201, tags=["Logs"],
              summary="Create log record (Mohamed Kassem)",
              description="Administrator or service token. user_id may be null for an unknown actor. "
                          "An optional Idempotency-Key header makes retried deliveries return the stored record (200).")
    def create(data: LogCreate, response: Response, user: Principal = Depends(admin),
               idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", min_length=1, max_length=100)] = None):
        record, created = repo.create(data, idempotency_key)
        if not created:
            response.status_code = 200
        return record

    @app.get(f"{PREFIX}/logs", response_model=list[LogRecord], tags=["Logs"],
             summary="Retrieve all logs (Mohamed Kassem)")
    def list_all(user: Principal = Depends(oversight)):
        return repo.list()

    @app.get(f"{PREFIX}/logs/search", response_model=list[LogRecord], tags=["Logs"],
             summary="Search logs (Mohamed Kassem)",
             description="Optional filters combined with AND: user_id, date (YYYY-MM-DD, UTC day), "
                         "action, severity, related_service.")
    def search(filters: Annotated[LogSearch, Query()], user: Principal = Depends(investigators)):
        return repo.list(filters.model_dump(mode="json", exclude_none=True))

    @app.get(f"{PREFIX}/logs/user/{{user_id}}", response_model=list[LogRecord], tags=["Logs"],
             summary="Retrieve logs by user (Mohamed Kassem)",
             description="Returns every activity recorded for the user, or an empty array when there are none.")
    def by_user(user_id: Annotated[str, Path(min_length=1, max_length=255)], user: Principal = Depends(oversight)):
        return repo.list({"user_id": user_id})

    @app.get(f"{PREFIX}/logs/{{log_id}}", response_model=LogRecord, tags=["Logs"],
             summary="Retrieve specific log (Mohamed Kassem)")
    def get(log_id: Id, user: Principal = Depends(investigators)):
        return repo.get(log_id)

    @app.delete(f"{PREFIX}/logs/{{log_id}}", status_code=204, tags=["Logs"],
                summary="Delete log (Mohamed Kassem)")
    def delete(log_id: Id, user: Principal = Depends(admin)):
        repo.delete(log_id, user.user_id)
        return Response(status_code=204)

    return app
