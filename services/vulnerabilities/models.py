import re
from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import Field, field_validator

from shared.models import Severity, ShortText, StrictModel, Text, UpdateModel

Score = Annotated[float, Field(ge=0, le=10, strict=True, allow_inf_nan=False)]


class VulnerabilityStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATION = "Under Investigation"
    PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class VulnerabilityCreate(StrictModel):
    title: ShortText
    description: Text
    cve_identifier: ShortText
    cvss_score: Score
    severity: Severity
    affected_asset_id: Annotated[int, Field(gt=0, strict=True)]
    discovery_source: ShortText

    @field_validator("cve_identifier")
    @classmethod
    def cve_format(cls, value):
        value = value.upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value):
            raise ValueError("CVE identifier must have the format CVE-YYYY-NNNN (at least four sequence digits)")
        return value


class VulnerabilityUpdate(UpdateModel):
    description: Text | None = None
    severity: Severity | None = None
    status: VulnerabilityStatus | None = None
    cvss_score: Score | None = None
    resolution_date: datetime | None = None

    @field_validator("resolution_date")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Resolution date must include a timezone")
        return value


class VulnerabilitySearch(StrictModel):
    cve_identifier: Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")] | None = None
    severity: Severity | None = None
    affected_asset_id: Annotated[int, Field(gt=0)] | None = None
    status: VulnerabilityStatus | None = None


class VulnerabilityRecord(VulnerabilityCreate):
    id: int
    status: VulnerabilityStatus
    creation_date: str
    resolution_date: str | None
