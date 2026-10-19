"""Local test tokens only. This is not the Users/Login service."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

from shared.auth import Role
from shared.config import Settings


def issue(settings, role, user_id="local-test-user", status="Active", minutes=30):
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "role": role, "account_status": status,
                       "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                       "iat": now, "exp": now + timedelta(minutes=minutes)},
                      settings.jwt_secret, algorithm="HS256")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postman", action="store_true", help="Write ignored local Postman environment")
    args = parser.parse_args()
    settings = Settings.from_env()
    tokens = {name: issue(settings, role.value, f"local-{name}") for name, role in {
        "admin_token": Role.ADMIN, "analyst_token": Role.ANALYST,
        "auditor_token": Role.AUDITOR, "user_token": Role.USER,
    }.items()}
    if args.postman:
        base = Path("postman/AliNaji.environment.json")
        env = json.loads(base.read_text(encoding="utf-8"))
        for entry in env["values"]:
            if entry["key"] in tokens:
                entry["value"] = tokens[entry["key"]]
        target = Path("postman/AliNaji.environment.local.json")
        target.write_text(json.dumps(env, indent=2), encoding="utf-8")
        print(f"Created {target}; tokens expire in 30 minutes. Never commit this file.")
    else:
        print(json.dumps(tokens, indent=2))


if __name__ == "__main__":
    main()
