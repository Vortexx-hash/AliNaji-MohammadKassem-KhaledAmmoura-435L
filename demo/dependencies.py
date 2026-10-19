"""Read-only sample dependencies and an idempotent demo audit receiver. Not real team services."""
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Path as PathParam
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import field_validator

from shared.auth import Role
from shared.config import PREFIX, Settings
from shared.database import Database
from shared.errors import install_handlers
from shared.models import ShortText, StrictModel, Text

BASE = f"{PREFIX}/demo"
SCHEMA = """
CREATE TABLE IF NOT EXISTS fixture_activities (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    related_service TEXT NOT NULL,
    origin TEXT NOT NULL CHECK(origin IN ('synthetic_fixture','actual_demo_api_event'))
);
"""


def load_fixtures():
    return json.loads(Path(__file__).with_name("fixtures.json").read_text(encoding="utf-8"))


class DemoEvent(StrictModel):
    user_id: str | int | None
    action: ShortText
    description: Text
    timestamp: datetime
    severity: Literal["Information", "Warning", "Error", "Critical"]
    related_service: ShortText

    @field_validator("timestamp")
    @classmethod
    def aware_timestamp(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include a timezone")
        return value


def create_app(settings: Settings | None = None, run_id="manual"):
    settings = settings or Settings.from_env()
    fixtures = load_fixtures()
    db = Database(settings.data_dir / "demo_dependencies.db")

    @asynccontextmanager
    async def lifespan(app):
        db.initialize(SCHEMA)
        with db.connect() as conn:
            for i, event in enumerate(fixtures["activities"]):
                timestamp = (datetime.now(timezone.utc) - timedelta(minutes=10 + i)).isoformat()
                conn.execute("INSERT OR IGNORE INTO fixture_activities VALUES (?,?,?,?,?,?,?,?)", (
                    event["id"], event["user_id"], event["action"], event["description"], timestamp,
                    event["severity"], event["related_service"], "synthetic_fixture"))
        yield

    app = FastAPI(title="SYNTHETIC DEMO dependencies (Ali Naji)", lifespan=lifespan,
                  description=fixtures["description"], docs_url=f"{BASE}/docs", redoc_url=None,
                  swagger_ui_oauth2_redirect_url=f"{BASE}/docs/oauth2-redirect",
                  openapi_url=f"{BASE}/openapi.json")
    app.state.db = db
    install_handlers(app)
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def mark_demo(request, call_next):
        response = await call_next(request)
        response.headers["X-Lab-Mode"] = "synthetic-dependencies"
        return response

    def access(*roles):
        def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
            try:
                if credentials is None:
                    raise ValueError("Missing token")
                claims = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"],
                                    issuer=settings.jwt_issuer, audience=settings.jwt_audience,
                                    options={"require": ["sub", "exp", "iat", "role", "account_status"]})
                if claims["account_status"] != "Active":
                    raise ValueError("Inactive account")
                role = Role(claims["role"])
            except (jwt.InvalidTokenError, ValueError, TypeError):
                raise HTTPException(401, "Valid local demo bearer token required")
            if role not in roles:
                raise HTTPException(403, "Demo fixture access denied")
        return authorize

    readers = access(Role.ADMIN, Role.AUDITOR)

    @app.get(f"{BASE}/health")
    def health():
        return {"status": "ok", "mode": "synthetic-dependencies", "run_id": run_id}

    @app.get(f"{BASE}/users", dependencies=[Depends(readers)])
    def users():
        return fixtures["users"]

    @app.get(f"{BASE}/assets", dependencies=[Depends(readers)])
    def assets():
        return fixtures["assets"]

    @app.get(f"{BASE}/assets/{{asset_id}}", dependencies=[Depends(access(Role.ADMIN, Role.ANALYST, Role.AUDITOR))])
    def asset(asset_id: Annotated[int, PathParam(gt=0)]):
        for record in fixtures["assets"]:
            if record["id"] == asset_id:
                return record
        raise HTTPException(404, "Demo asset not found")

    @app.get(f"{BASE}/incidents", dependencies=[Depends(readers)])
    def incidents():
        return fixtures["incidents"]

    @app.get(f"{BASE}/logs", dependencies=[Depends(readers)])
    def logs():
        with db.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM fixture_activities ORDER BY timestamp,id")]

    @app.post(f"{BASE}/logs", dependencies=[Depends(access(Role.ADMIN))], status_code=201)
    def receive_event(event: DemoEvent, event_id: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=100)]):
        with db.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO fixture_activities VALUES (?,?,?,?,?,?,?,?)", (
                event_id, None if event.user_id is None else str(event.user_id), event.action,
                event.description, event.timestamp.astimezone(timezone.utc).isoformat(),
                event.severity, event.related_service, "actual_demo_api_event"))
        return {"id": event_id, "mode": "synthetic-dependencies"}

    return app
