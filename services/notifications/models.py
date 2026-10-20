from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field

from shared.models import Severity, ShortText, StrictModel, Text

UserId = Annotated[int, Field(gt=0, strict=True)]


class NotificationType(str, Enum):
    INCIDENT_ASSIGNMENT = "Incident Assignment"
    SECURITY_ALERT = "Security Alert"
    SYSTEM_NOTIFICATION = "System Notification"
    THREAT_ALERT = "Threat Alert"
    VULNERABILITY_ALERT = "Vulnerability Alert"


class NotificationStatus(str, Enum):
    UNREAD = "Unread"
    READ = "Read"


class NotificationCreate(StrictModel):
    user_id: UserId
    title: ShortText
    message: Text
    notification_type: NotificationType
    severity: Severity


class NotificationSearch(StrictModel):
    user_id: Annotated[int, Field(gt=0)] | None = None
    notification_type: NotificationType | None = None
    severity: Severity | None = None
    status: NotificationStatus | None = None


class NotificationRecord(NotificationCreate):
    id: int
    status: NotificationStatus
    creation_date: str
    read_date: str | None
