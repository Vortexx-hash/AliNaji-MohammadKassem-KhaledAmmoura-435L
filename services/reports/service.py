from collections import Counter

from services.reports.models import ActivitySource, AssetSource, IncidentSource, ThreatSource, UserSource, VulnerabilitySource
from services.threats.models import ThreatType
from services.vulnerabilities.models import VulnerabilityStatus
from shared.audit import utcnow
from shared.models import Severity

INCIDENT_STATES = ["Open", "Under Investigation", "Mitigated", "Resolved", "Closed"]


def group(records, field, categories=()):
    counts = Counter(getattr(record, field) for record in records)
    return {str(getattr(key, "value", key)): counts.get(key, 0) for key in (categories or sorted(counts))}


class ReportService:
    models = {"users": UserSource, "assets": AssetSource, "incidents": IncidentSource,
              "threats": ThreatSource, "vulnerabilities": VulnerabilitySource, "logs": ActivitySource}

    def __init__(self, settings, upstream):
        self.settings, self.upstream = settings, upstream

    def collect(self, names, token):
        return {name: self.upstream.records(self.settings.sources.get(name, ""), token, name, self.models[name])
                for name in names}

    def generate(self, kind, token):
        names = list(self.models) if kind == "summary" else ["logs" if kind == "activity" else kind]
        data = self.collect(names, token)
        metadata = {"generated_at": utcnow(), "sources": names}
        if kind == "summary":
            incidents = data["incidents"]
            result = {
                "users": len(data["users"]), "assets": len(data["assets"]), "incidents": len(incidents),
                "open_incidents": sum(r.status == "Open" for r in incidents),
                "unresolved_incidents": sum(r.status not in ("Resolved", "Closed") for r in incidents),
                "incidents_by_severity": group(incidents, "severity", list(Severity)),
                "threats": len(data["threats"]),
                "critical_threats": sum(r.severity == Severity.CRITICAL for r in data["threats"]),
                "vulnerabilities": len(data["vulnerabilities"]),
                "critical_vulnerabilities": sum(r.severity == Severity.CRITICAL for r in data["vulnerabilities"]),
                "recent_security_activities": sorted(data["logs"], key=lambda r: r.timestamp, reverse=True)[:10],
            }
        elif kind == "incidents":
            records = data[kind]
            result = {"total_incidents": len(records), "incidents_by_severity": group(records, "severity", list(Severity)),
                      "incidents_by_status": group(records, "status", INCIDENT_STATES)}
        elif kind == "assets":
            records = data[kind]
            result = {"total_assets": len(records), "critical_assets": sum(r.criticality_level == Severity.CRITICAL for r in records),
                      "assets_by_type": group(records, "asset_type")}
        elif kind == "threats":
            records = data[kind]
            result = {"total_threats": len(records), "threats_by_severity": group(records, "severity", list(Severity)),
                      "threats_by_type": group(records, "threat_type", list(ThreatType)),
                      "recent_added_threats": sorted(records, key=lambda r: r.date_added, reverse=True)[:10]}
        elif kind == "vulnerabilities":
            records = data[kind]
            result = {"total_vulnerabilities": len(records),
                      "vulnerabilities_by_severity": group(records, "severity", list(Severity)),
                      "vulnerabilities_by_status": group(records, "status", list(VulnerabilityStatus)),
                      "critical_vulnerabilities": sum(r.severity == Severity.CRITICAL for r in records)}
        else:
            records = data["logs"]
            counts = Counter(r.action for r in records)
            # These are LOGIN events; protected-resource token failures are not login attempts.
            success = counts["LOGIN_SUCCESS"]
            failure = counts["LOGIN_FAILED"]
            result = {"total_user_activities": len(records), "login_attempts": success + failure,
                      "failed_login_attempts": failure,
                      "most_performed_actions": [{"action": action, "count": count}
                                                 for action, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:10]],
                      "recent_security_activities": sorted(records, key=lambda r: r.timestamp, reverse=True)[:10]}
        return {**metadata, **result}
