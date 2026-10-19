import ipaddress
import re
from enum import Enum
from typing import Annotated

from pydantic import Field, model_validator

from shared.models import Severity, ShortText, StrictModel, Text, UpdateModel


class ThreatType(str, Enum):
    IP = "IP Address"
    DOMAIN = "Domain"
    HASH = "File Hash"
    SIGNATURE = "Malware Signature"
    OTHER = "Other Indicators"


class ThreatCreate(StrictModel):
    threat_type: ThreatType
    threat_value: ShortText
    description: Text
    severity: Severity
    source: ShortText

    @model_validator(mode="after")
    def validate_indicator(self):
        value = self.threat_value
        if self.threat_type == ThreatType.IP:
            self.threat_value = str(ipaddress.ip_address(value))
        elif self.threat_type == ThreatType.DOMAIN:
            value = value.rstrip(".").lower()
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                raise ValueError("Domain must be a hostname, not an IP address")
            if len(value) > 253 or not re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
                raise ValueError("Invalid domain; use a hostname without scheme, port or path")
            self.threat_value = value
        elif self.threat_type == ThreatType.HASH:
            if len(value) not in (32, 40, 64) or not re.fullmatch(r"[0-9a-fA-F]+", value):
                raise ValueError("File Hash must be a hexadecimal MD5, SHA-1 or SHA-256 value")
            self.threat_value = value.lower()
        if any(ord(c) < 32 or ord(c) == 127 for c in self.threat_value):
            raise ValueError("Threat value cannot contain control characters")
        return self


class ThreatUpdate(UpdateModel):
    description: Text | None = None
    severity: Severity | None = None
    source: ShortText | None = None


class ThreatSearch(StrictModel):
    threat_type: ThreatType | None = None
    threat_value: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    severity: Severity | None = None
    source: Annotated[str, Field(min_length=1, max_length=255)] | None = None


class ThreatRecord(ThreatCreate):
    id: int
    date_added: str
