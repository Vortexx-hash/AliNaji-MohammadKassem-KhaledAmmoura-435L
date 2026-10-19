"""Retry durable audit events after the teammate's audit endpoint is configured."""
import argparse

from shared.audit import AuditOutbox
from shared.config import Settings
from shared.database import Database, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["threats", "vulnerabilities", "reports"])
    args = parser.parse_args()
    settings = Settings.from_env()
    if not settings.audit_post_url or not settings.audit_service_token:
        parser.error("Set AUDIT_POST_URL and AUDIT_SERVICE_TOKEN first")
    names = {"threats": "Threat Intelligence", "vulnerabilities": "Vulnerability Management", "reports": "Security Reports"}
    db = Database(settings.data_dir / f"{args.service}.db")
    db.initialize(schema("audit_outbox.sql"))
    print(f"Delivered {AuditOutbox(db, settings, names[args.service]).flush()} event(s)")


if __name__ == "__main__":
    main()
