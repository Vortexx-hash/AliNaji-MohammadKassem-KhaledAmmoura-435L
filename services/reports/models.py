from datetime import datetime
from typing import Annotated, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from services.threats.models import ThreatType
from services.vulnerabilities.models import VulnerabilityStatus
from shared.models import Severity


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    id: Annotated[int, Field(gt=0, strict=True)] | Annotated[str, Field(min_length=1, strict=True)]


class UserSource(SourceRecord):
    pass


class AssetSource(SourceRecord):
    asset_type: Annotated[str, Field(min_length=1)]
    criticality_level: Severity


class IncidentSource(SourceRecord):
    severity: Severity
    status: Literal["Open", "Under Investigation", "Mitigated", "Resolved", "Closed"]


class ThreatSource(SourceRecord):
    threat_type: ThreatType
    threat_value: str
    description: str
    severity: Severity
    source: str
    date_added: datetime

    @field_validator("date_added")
    @classmethod
    def aware_date(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Threat timestamps must include a timezone")
        return value


class VulnerabilitySource(SourceRecord):
    severity: Severity
    status: VulnerabilityStatus


class ActivitySource(SourceRecord):
    user_id: int | str | None = None
    action: str = Field(validation_alias=AliasChoices("action", "action_performed"), min_length=1)
    description: str
    timestamp: datetime
    severity: Literal["Information", "Warning", "Error", "Critical"]
    related_service: str

    @field_validator("timestamp")
    @classmethod
    def aware_date(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Activity timestamps must include a timezone")
        return value


class ReportMetadata(BaseModel):
    generated_at: str
    sources: list[str]


class IncidentReport(ReportMetadata):
    total_incidents: int
    incidents_by_severity: dict[str, int]
    incidents_by_status: dict[str, int]


class AssetReport(ReportMetadata):
    total_assets: int
    critical_assets: int
    assets_by_type: dict[str, int]


class ThreatReport(ReportMetadata):
    total_threats: int
    threats_by_severity: dict[str, int]
    threats_by_type: dict[str, int]
    recent_added_threats: list[ThreatSource]


class VulnerabilityReport(ReportMetadata):
    total_vulnerabilities: int
    vulnerabilities_by_severity: dict[str, int]
    vulnerabilities_by_status: dict[str, int]
    critical_vulnerabilities: int


class ActionCount(BaseModel):
    action: str
    count: int


class ActivityReport(ReportMetadata):
    total_user_activities: int
    login_attempts: int
    failed_login_attempts: int
    most_performed_actions: list[ActionCount]
    recent_security_activities: list[ActivitySource]


class SummaryReport(ReportMetadata):
    users: int
    assets: int
    incidents: int
    open_incidents: int
    unresolved_incidents: int
    incidents_by_severity: dict[str, int]
    threats: int
    critical_threats: int
    vulnerabilities: int
    critical_vulnerabilities: int
    recent_security_activities: list[ActivitySource]
