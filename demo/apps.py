"""Wrap the actual owned service factories with visible demo labels only."""
from shared.config import Settings


def create_app(service: str, settings: Settings | None = None):
    if service == "threats":
        from services.threats.app import create_app as factory
    elif service == "vulnerabilities":
        from services.vulnerabilities.app import create_app as factory
    elif service == "reports":
        from services.reports.app import create_app as factory
    else:
        raise ValueError("Unknown demo service")
    app = factory(settings)
    app.title = "DEMO - " + app.title
    app.description = "Actual owned API running with explicitly synthetic external dependency fixtures. Not proof of teammate-service integration."

    @app.middleware("http")
    async def mark_demo(request, call_next):
        response = await call_next(request)
        response.headers["X-Lab-Mode"] = "synthetic-dependencies"
        return response

    return app
