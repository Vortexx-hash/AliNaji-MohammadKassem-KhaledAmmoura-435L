from typing import Annotated

from fastapi import Depends, Path, Query, Request, Response

from services.notifications.models import NotificationCreate, NotificationRecord, NotificationSearch
from services.notifications.repository import NotificationRepository
from shared.app import create_service
from shared.auth import Principal, Role, forbid, require
from shared.config import Settings
from shared.upstream import UpstreamClient

PREFIX = "/MohamedKassem"
AUTHOR = "Mohamed Kassem"
Id = Annotated[int, Path(gt=0)]
# These roles only see notifications addressed to them; administrators and auditors see all.
OWN_ONLY = {Role.USER, Role.ANALYST}


def create_app(settings: Settings | None = None):
    app = create_service("Notification and Alert Management", "notifications.db", settings or Settings.from_env(),
                         "notifications.sql", PREFIX, AUTHOR)
    repo = NotificationRepository(app.state.db, app.state.audit)
    app.state.upstream = UpstreamClient()
    everyone = require(Role.ADMIN, Role.ANALYST, Role.USER, Role.AUDITOR)

    def check_owner(request, user, owner_id):
        if user.role in OWN_ONLY and str(owner_id) != user.user_id:
            forbid(request, user)

    @app.post(f"{PREFIX}/notifications", response_model=NotificationRecord, status_code=201, tags=["Notifications"],
              summary="Create notification (Mohamed Kassem)",
              description="Administrator or service token. The recipient is verified through the Users service.")
    def create(data: NotificationCreate, user: Principal = Depends(require(Role.ADMIN))):
        recipient = app.state.upstream.user(app.state.settings.sources.get("users", ""), data.user_id, user.token)
        return repo.create(data, recipient, user.user_id)

    @app.get(f"{PREFIX}/notifications/search", response_model=list[NotificationRecord], tags=["Notifications"],
             summary="Search notifications (Mohamed Kassem)",
             description="Optional exact filters combined with AND: user_id, notification_type, severity, status. "
                         "Analyst searches are limited to their own notifications.")
    def search(filters: Annotated[NotificationSearch, Query()], request: Request,
               user: Principal = Depends(require(Role.ADMIN, Role.ANALYST, Role.AUDITOR))):
        values = filters.model_dump(mode="json", exclude_none=True)
        if user.role in OWN_ONLY:
            check_owner(request, user, values.get("user_id", user.user_id))
            values["user_id"] = int(user.user_id) if user.user_id.isdigit() else 0
        return repo.list(values)

    @app.get(f"{PREFIX}/notifications/user/{{user_id}}", response_model=list[NotificationRecord],
             tags=["Notifications"], summary="Retrieve user notifications (Mohamed Kassem)",
             description="Returns the user's notifications, or an empty array when there are none.")
    def by_user(user_id: Id, request: Request, user: Principal = Depends(everyone)):
        check_owner(request, user, user_id)
        return repo.list({"user_id": user_id})

    @app.get(f"{PREFIX}/notifications/{{notification_id}}", response_model=NotificationRecord,
             tags=["Notifications"], summary="Retrieve specific notification (Mohamed Kassem)")
    def get(notification_id: Id, request: Request, user: Principal = Depends(everyone)):
        row = repo.get(notification_id)
        check_owner(request, user, row["user_id"])
        return row

    @app.put(f"{PREFIX}/notifications/{{notification_id}}/read", response_model=NotificationRecord,
             tags=["Notifications"], summary="Mark notification as read (Mohamed Kassem)",
             description="Sets status Read and records read_date once. Repeating the call keeps the original read_date.")
    def mark_read(notification_id: Id, request: Request,
                  user: Principal = Depends(require(Role.ADMIN, Role.ANALYST, Role.USER))):
        check_owner(request, user, repo.get(notification_id)["user_id"])
        return repo.mark_read(notification_id, user.user_id)

    @app.delete(f"{PREFIX}/notifications/{{notification_id}}", status_code=204, tags=["Notifications"],
                summary="Delete notification (Mohamed Kassem)")
    def delete(notification_id: Id, user: Principal = Depends(require(Role.ADMIN))):
        repo.delete(notification_id, user.user_id)
        return Response(status_code=204)

    return app
