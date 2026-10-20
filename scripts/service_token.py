"""Print the long-lived service token every service uses to deliver audit events to the Logs service
(AUDIT_SERVICE_TOKEN). It carries the administrator role because POST /logs is administrator only."""
import argparse

from scripts.dev_tokens import issue
from scripts.seed_owned import load_local_env
from shared.auth import Role
from shared.config import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()
    load_local_env()
    print(issue(Settings.from_env(), Role.ADMIN.value, "audit-service", minutes=args.days * 24 * 60))


if __name__ == "__main__":
    main()
