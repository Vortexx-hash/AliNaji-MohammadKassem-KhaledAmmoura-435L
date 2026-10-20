"""Create the first Security Administrator (Mohamed Kassem).

The register API only lets an existing administrator create privileged accounts, so the very first
administrator is created here with the same validation, bcrypt hashing and audit event as the API.
"""
import argparse
import getpass

from fastapi import HTTPException
from pydantic import ValidationError

from scripts.seed_owned import load_local_env
from services.users.models import UserRegister
from services.users.repository import UserRepository
from shared.audit import AuditOutbox
from shared.config import Settings
from shared.database import Database, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", default="admin1")
    parser.add_argument("--full-name", default="Lab Security Administrator")
    parser.add_argument("--email", default="admin1@example.com")
    parser.add_argument("--department", default="Security Operations")
    args = parser.parse_args()
    load_local_env()
    settings = Settings.from_env()
    password = getpass.getpass(f"Password for {args.username}: ")
    try:
        data = UserRegister(full_name=args.full_name, username=args.username, email=args.email,
                            password=password, department=args.department, role="Security Administrator")
    except ValidationError as exc:
        parser.error("; ".join(error["msg"] for error in exc.errors()))
    db = Database(settings.data_dir / "users.db")
    db.initialize(schema("audit_outbox.sql"), schema("users.sql"))
    try:
        user = UserRepository(db, AuditOutbox(db, settings, "Users and Identity Management"), settings).register(data, None)
    except HTTPException as exc:
        parser.error(exc.detail)
    print(f"Created administrator {user['username']} with id {user['id']}. Log in through POST /MohamedKassem/users/login.")


if __name__ == "__main__":
    main()
