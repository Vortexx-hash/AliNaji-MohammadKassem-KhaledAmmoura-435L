from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.audit import AuditOutbox
from shared.config import PREFIX, Settings
from shared.database import Database, schema
from shared.errors import install_handlers


def create_service(name: str, db_name: str, settings: Settings, service_schema: str | None = None):
    db = Database(settings.data_dir / db_name)
    audit = AuditOutbox(db, settings, name)

    @asynccontextmanager
    async def lifespan(app):
        scripts = [schema("audit_outbox.sql")]
        if service_schema:
            scripts.append(schema(service_schema))
        db.initialize(*scripts)
        yield

    app = FastAPI(title=f"{name} (Ali Naji)", version="1.0.0", lifespan=lifespan,
                  docs_url=f"{PREFIX}/docs", redoc_url=f"{PREFIX}/redoc",
                  openapi_url=f"{PREFIX}/openapi.json")
    app.state.settings, app.state.db, app.state.audit = settings, db, audit
    install_handlers(app)

    @app.get(f"{PREFIX}/health", tags=["Operations"], summary="Check service availability (Ali Naji)")
    def health():
        with db.connect() as conn:
            conn.execute("SELECT 1")
            pending = conn.execute("""SELECT count(*) FROM audit_outbox o LEFT JOIN audit_delivery d
                                   ON o.event_id=d.event_id WHERE d.event_id IS NULL""").fetchone()[0]
        return {"status": "ok", "service": name, "pending_audit_events": pending}

    return app
