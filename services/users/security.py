from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

ROUNDS = 12
TOKEN_MINUTES = 60
# Compared against when the account does not exist, so response time does not reveal valid usernames.
DUMMY_HASH = bcrypt.hashpw(b"unused-password", bcrypt.gensalt(ROUNDS))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(ROUNDS)).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    candidate = password.encode()[:72]
    if password_hash is None:
        bcrypt.checkpw(candidate, DUMMY_HASH)
        return False
    return bcrypt.checkpw(candidate, password_hash.encode())


def issue_token(settings, user) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user["id"]), "role": user["role"], "account_status": user["account_status"],
                       "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                       "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)},
                      settings.jwt_secret, algorithm="HS256")
