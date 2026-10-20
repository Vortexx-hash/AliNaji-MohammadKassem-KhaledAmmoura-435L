from typing import Annotated

from fastapi import Depends, HTTPException, Path, Request, Response
from fastapi.security import HTTPAuthorizationCredentials

from services.users.models import LoginRequest, LoginResponse, UserRecord, UserRegister, UserUpdate
from services.users.repository import UserRepository
from shared.app import create_service
from shared.auth import Principal, Role, bearer, forbid, require
from shared.config import Settings
from shared.upstream import UpstreamClient

PREFIX = "/MohamedKassem"
AUTHOR = "Mohamed Kassem"
Id = Annotated[int, Path(gt=0)]
ADMIN_ONLY_FIELDS = {"role", "account_status"}


def create_app(settings: Settings | None = None):
    app = create_service("Users and Identity Management", "users.db", settings or Settings.from_env(),
                         "users.sql", PREFIX, AUTHOR)
    repo = UserRepository(app.state.db, app.state.audit, app.state.settings)
    app.state.upstream = UpstreamClient()
    registrar = require(Role.ADMIN, Role.USER)

    @app.post(f"{PREFIX}/users/register", response_model=UserRecord, status_code=201, tags=["Users"],
              summary="User registration (Mohamed Kassem)",
              description="Public self-registration creates Regular Employee/User accounts only. "
                          "A Security Administrator token is required to register any other role.")
    def register(data: UserRegister, request: Request,
                 credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        caller = registrar(request, credentials) if credentials else None
        if data.role != Role.USER and (caller is None or caller.role != Role.ADMIN):
            if caller is None:
                app.state.audit.denied(None, "PERMISSION_DENIED", f"Anonymous registration as {data.role.value}")
                raise HTTPException(403, "Only a Security Administrator can register this role")
            forbid(request, caller)
        return repo.register(data, caller.user_id if caller else None)

    @app.post(f"{PREFIX}/users/login", response_model=LoginResponse, tags=["Users"],
              summary="User login (Mohamed Kassem)",
              description="Verify username or email and password; returns a signed JWT bearer token.")
    def login(data: LoginRequest):
        return repo.login(data)

    @app.get(f"{PREFIX}/users", response_model=list[UserRecord], tags=["Users"],
             summary="Retrieve all users (Mohamed Kassem)")
    def list_all(user: Principal = Depends(require(Role.ADMIN, Role.AUDITOR))):
        return repo.list()

    @app.get(f"{PREFIX}/users/{{username}}", response_model=UserRecord, tags=["Users"],
             summary="Retrieve user by username (Mohamed Kassem)")
    def get(username: Annotated[str, Path(min_length=1, max_length=254)], request: Request,
            user: Principal = Depends(require(Role.ADMIN, Role.AUDITOR, Role.USER))):
        row = repo.get_by_username(username)
        if user.role == Role.USER and (row is None or str(row["id"]) != user.user_id):
            forbid(request, user)
        if row is None:
            raise HTTPException(404, "User not found")
        return row

    @app.put(f"{PREFIX}/users/{{user_id}}", response_model=UserRecord, tags=["Users"],
             summary="Update user information (Mohamed Kassem)",
             description="Users update their own full_name, email and department. "
                         "Administrators can update any user, including role and account_status.")
    def update(user_id: Id, data: UserUpdate, request: Request,
               user: Principal = Depends(require(Role.ADMIN, Role.USER))):
        if user.role == Role.USER and (str(user_id) != user.user_id or data.model_fields_set & ADMIN_ONLY_FIELDS):
            forbid(request, user)
        before, after = repo.update(user_id, data, user.user_id)
        for field in ("role", "account_status"):
            if after[field] != before[field]:
                label = field.replace("_", " ")
                app.state.upstream.notify(
                    app.state.settings.notification_post_url, user.token, user_id, f"Your {label} was changed",
                    f"Your {label} changed from {before[field]} to {after[field]}.", "System Notification")
        return after

    @app.delete(f"{PREFIX}/users/{{user_id}}", status_code=204, tags=["Users"],
                summary="Delete user (Mohamed Kassem)")
    def delete(user_id: Id, user: Principal = Depends(require(Role.ADMIN))):
        repo.delete(user_id, user.user_id)
        return Response(status_code=204)

    return app
