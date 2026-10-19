import os
from dataclasses import dataclass, field
from pathlib import Path

PREFIX = "/AliNaji"


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    data_dir: Path = Path("data")
    jwt_issuer: str = "security-lab"
    jwt_audience: str = "security-services"
    identity_me_url: str = ""
    asset_detail_url: str = ""
    audit_post_url: str = ""
    audit_service_token: str = ""
    sources: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if len(self.jwt_secret) < 32 or self.jwt_secret.startswith("replace-"):
            raise ValueError("Set JWT_SECRET to a private random value of at least 32 characters")

    @classmethod
    def from_env(cls):
        return cls(
            jwt_secret=os.getenv("JWT_SECRET", ""),
            data_dir=Path(os.getenv("DATA_DIR", "data")),
            jwt_issuer=os.getenv("JWT_ISSUER", "security-lab"),
            jwt_audience=os.getenv("JWT_AUDIENCE", "security-services"),
            identity_me_url=os.getenv("IDENTITY_ME_URL", ""),
            asset_detail_url=os.getenv("ASSET_DETAIL_URL", ""),
            audit_post_url=os.getenv("AUDIT_POST_URL", ""),
            audit_service_token=os.getenv("AUDIT_SERVICE_TOKEN", ""),
            sources={name: os.getenv(f"{name.upper()}_LIST_URL", default) for name, default in {
                "users": "", "assets": "", "incidents": "", "logs": "",
                "threats": "http://127.0.0.1:8004/AliNaji/threats",
                "vulnerabilities": "http://127.0.0.1:8007/AliNaji/vulnerabilities",
            }.items()},
        )
