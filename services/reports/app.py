from fastapi import Depends

from services.reports.models import ActivityReport, AssetReport, IncidentReport, SummaryReport, ThreatReport, VulnerabilityReport
from services.reports.service import ReportService
from shared.app import create_service
from shared.auth import Principal, Role, require
from shared.config import PREFIX, Settings
from shared.upstream import UpstreamClient


def create_app(settings: Settings | None = None):
    app = create_service("Security Reports", "reports.db", settings or Settings.from_env())
    app.state.upstream = UpstreamClient()
    access = require(Role.ADMIN, Role.AUDITOR)

    def endpoint(kind):
        def generate(user: Principal = Depends(access)):
            result = ReportService(app.state.settings, app.state.upstream).generate(kind, user.token)
            with app.state.db.connect() as conn:
                app.state.audit.record(conn, user.user_id, "REPORT_GENERATED", f"Generated {kind} report")
            app.state.audit.flush()
            return result
        return generate

    for kind, model in {"summary": SummaryReport, "incidents": IncidentReport, "assets": AssetReport,
                        "threats": ThreatReport, "vulnerabilities": VulnerabilityReport, "activity": ActivityReport}.items():
        app.add_api_route(f"{PREFIX}/reports/{kind}", endpoint(kind), methods=["GET"], response_model=model,
                          name=f"generate_{kind}_report", summary=f"Generate {kind} report (Ali Naji)", tags=["Reports"],
                          description="Fetch live records from configured source services and aggregate them. Administrator/Auditor only. Returns 503 if a required source is unavailable or incomplete.")

    return app
