from datetime import date as Date, datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from shared.models import ShortText, StrictModel, Text


class LogSeverity(str, Enum):
    INFORMATION = "Information"
    WARNING = "Warning"
    ERROR = "Error"
    CRITICAL = "Critical"


class LogCreate(StrictModel):
    user_id: Annotated[int, Field(gt=0, strict=True)] | ShortText | None
    action: ShortText
    description: Text
    severity: LogSeverity
    related_service: ShortText
    timestamp: datetime | None = None

    @field_validator("timestamp")
    @classmethod
    def original_time(cls, value):
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include a timezone")
        if value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("Timestamp cannot be in the future")
        return value


class LogSearch(StrictModel):
    user_id: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    date: Date | None = None
    action: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    severity: LogSeverity | None = None
    related_service: Annotated[str, Field(min_length=1, max_length=255)] | None = None


class LogRecord(BaseModel):
    id: int
    user_id: str | None
    action: str
    description: str
    timestamp: str
    severity: LogSeverity
    related_service: str
