from dataclasses import dataclass
from enum import Enum

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(str, Enum):
    ADMIN = "Security Administrator"
    ANALYST = "Security Analyst"
    USER = "Regular Employee/User"
    AUDITOR = "Auditor"


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role
    token: str


bearer = HTTPBearer(auto_error=False)


def require(*roles: Role):
    def authorize(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        settings, audit = request.app.state.settings, request.app.state.audit
        try:
            if not credentials:
                raise ValueError("Missing bearer token")
            claims = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"],
                                issuer=settings.jwt_issuer, audience=settings.jwt_audience,
                                options={"require": ["sub", "exp", "iat", "iss", "aud", "role", "account_status"]})
            if not isinstance(claims["sub"], str) or not claims["sub"].strip():
                raise ValueError("Invalid subject")
            if claims["account_status"] != "Active":
                raise ValueError("Account is not active")
            principal = Principal(claims["sub"], Role(claims["role"]), credentials.credentials)
        except (jwt.InvalidTokenError, ValueError, TypeError):
            audit.denied(None, "AUTHENTICATION_FAILED", f"{request.method} {request.url.path}")
            raise HTTPException(401, "Missing, invalid, expired token or inactive account",
                                headers={"WWW-Authenticate": "Bearer"})
        if settings.identity_me_url:
            try:
                response = httpx.get(settings.identity_me_url, timeout=3, follow_redirects=False,
                                     headers={"Authorization": f"Bearer {principal.token}"})
                if response.status_code in (401, 403, 404):
                    audit.denied(principal.user_id, "AUTHENTICATION_FAILED", "Identity service rejected account")
                    raise HTTPException(401, "Account no longer authorized", headers={"WWW-Authenticate": "Bearer"})
                response.raise_for_status()
                identity = response.json()
                if isinstance(identity, dict) and "data" in identity:
                    identity = identity["data"]
                if (str(identity["id"]) != principal.user_id or identity["account_status"] != "Active"
                        or identity["role"] != principal.role.value):
                    audit.denied(principal.user_id, "AUTHENTICATION_FAILED", "Account status or role changed")
                    raise HTTPException(401, "Account status or role changed; log in again")
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                raise HTTPException(503, "Identity service unavailable or returned invalid data")
        if principal.role not in roles:
            audit.denied(principal.user_id, "PERMISSION_DENIED", f"{request.method} {request.url.path}")
            raise HTTPException(403, "User does not have permission to perform this operation")
        return principal

    return authorize
