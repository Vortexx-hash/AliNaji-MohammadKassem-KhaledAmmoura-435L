import re
from enum import Enum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, StringConstraints, model_validator

from shared.auth import Role
from shared.models import ShortText, StrictModel, UpdateModel


class AccountStatus(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    SUSPENDED = "Suspended"


def check_username(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", value):
        raise ValueError("Username must be 3 to 30 letters, digits or underscores")
    return value


def check_email(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", value):
        raise ValueError("Invalid email format")
    return value.lower()


def check_password(value: str) -> str:
    if len(value.encode()) > 72:
        raise ValueError("Password must be at most 72 bytes")
    if not (re.search(r"[A-Z]", value) and re.search(r"[a-z]", value)
            and re.search(r"[0-9]", value) and re.search(r"[^A-Za-z0-9]", value)):
        raise ValueError("Password must contain an uppercase letter, a lowercase letter, a digit and a symbol")
    return value


Username = Annotated[str, StringConstraints(strip_whitespace=True), AfterValidator(check_username)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, max_length=254), AfterValidator(check_email)]
Password = Annotated[str, StringConstraints(strip_whitespace=False, min_length=8), AfterValidator(check_password)]


class UserRegister(StrictModel):
    full_name: ShortText
    username: Username
    email: Email
    password: Password
    department: ShortText
    role: Role


class UserUpdate(UpdateModel):
    full_name: ShortText | None = None
    email: Email | None = None
    department: ShortText | None = None
    role: Role | None = None
    account_status: AccountStatus | None = None


class LoginRequest(StrictModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=254)] | None = None
    email: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=254)] | None = None
    password: Annotated[str, StringConstraints(strip_whitespace=False, min_length=1, max_length=255)]

    @model_validator(mode="after")
    def one_identifier(self):
        if (self.username is None) == (self.email is None):
            raise ValueError("Provide either username or email")
        return self


class UserRecord(BaseModel):
    id: int
    full_name: str
    username: str
    email: str
    department: str
    role: Role
    account_status: AccountStatus
    created_date: str
    last_login_date: str | None


class LoginResponse(BaseModel):
    message: str
    access_token: str
    token_type: str
    expires_in: int
    user: UserRecord
