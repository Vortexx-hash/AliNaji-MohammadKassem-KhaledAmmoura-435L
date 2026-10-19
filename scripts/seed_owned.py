"""Create sample records through running owned APIs, never through fake teammate services."""
import argparse
import os
from pathlib import Path

import httpx

from scripts.dev_tokens import issue
from shared.auth import Role
from shared.config import Settings


def load_local_env():
    path = Path(".env")
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                if key.strip().isidentifier():
                    os.environ.setdefault(key.strip(), value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-id", type=int, help="Also create sample vulnerabilities for this REAL asset")
    args = parser.parse_args()
    load_local_env()
    token = issue(Settings.from_env(), Role.ADMIN.value, "local-sample-author")
    headers = {"Authorization": "Bearer " + token}
    records = [
        {"threat_type": "IP Address", "threat_value": "203.0.113.8", "description": "Lab scanning indicator; High priority for investigation", "severity": "High", "source": "Lab sensor"},
        {"threat_type": "Domain", "threat_value": "phishing.example.com", "description": "Lab phishing domain; Critical due to credential risk", "severity": "Critical", "source": "Lab analysis"},
        {"threat_type": "File Hash", "threat_value": "ab" * 32, "description": "Lab SHA-256 indicator; Medium pending further analysis", "severity": "Medium", "source": "Lab scanner"},
        {"threat_type": "Other Indicators", "threat_value": "LAB-ATTACK-PATTERN", "description": "Lab attack pattern; Low confidence observation", "severity": "Low", "source": "Lab analysis"},
    ]
    with httpx.Client(timeout=10, headers=headers) as client:
        for record in records:
            response = client.post("http://127.0.0.1:8004/AliNaji/threats", json=record)
            if response.status_code not in (201, 409):
                raise SystemExit(f"Threat API failed: {response.status_code} {response.text}")
            print(f"Threat {record['threat_type']}: HTTP {response.status_code}")
        if args.asset_id:
            if args.asset_id <= 0:
                parser.error("asset-id must be positive")
            for severity, score in [("High", 8.1), ("Critical", 9.8)]:
                record = {"title": f"{severity} lab finding", "description": "Lab finding for a verified asset",
                          "cve_identifier": "CVE-2025-12345", "cvss_score": score, "severity": severity,
                          "affected_asset_id": args.asset_id, "discovery_source": "Lab scanner"}
                response = client.post("http://127.0.0.1:8007/AliNaji/vulnerabilities", json=record)
                if response.status_code != 201:
                    raise SystemExit(f"Vulnerability API failed: {response.status_code} {response.text}")
                print(f"Vulnerability {severity}: HTTP 201; id={response.json()['id']}")
    print("These are lab sample indicators, not claims about real malicious hosts or real CVE applicability.")


if __name__ == "__main__":
    main()
