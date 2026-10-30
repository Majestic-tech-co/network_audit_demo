from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, field_validator, model_validator
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "NetAudit"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str
    ENCRYPTION_KEY: str  # Must be exactly 32 characters for AES-256

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def encryption_key_length(cls, v: str) -> str:
        if len(v) != 32:
            raise ValueError(
                f"ENCRYPTION_KEY must be exactly 32 characters (got {len(v)}). "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(16))\""
            )
        return v
    @model_validator(mode="after")
    def reject_placeholder_secrets(self):
        """Refuse to start in production with example/default secrets."""
        if self.ENVIRONMENT == "production":
            for name in ("SECRET_KEY", "ENCRYPTION_KEY"):
                value = getattr(self, name).lower()
                if "change-this" in value or "changeme" in value:
                    raise ValueError(f"{name} is still a placeholder value; set a real secret in .env")
            if len(self.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters (openssl rand -hex 32)")
        return self

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    ALGORITHM: str = "HS256"

    # Database
    DATABASE_URL: str

    # Redis
    REDIS_URL: str

    # CORS
    CORS_ORIGINS: str = "https://localhost"

    # Cloudflare Turnstile (CAPTCHA on login/register). Unset = disabled.
    TURNSTILE_SECRET_KEY: Optional[str] = None

    @field_validator("CORS_ORIGINS")
    @classmethod
    def cors_no_wildcard(cls, v: str) -> str:
        if any(o.strip() == "*" for o in v.split(",")):
            raise ValueError("CORS_ORIGINS must list explicit origins, not *")
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    # ClamAV
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310
    QUARANTINE_PATH: str = "/quarantine"

    # VirusTotal (optional)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    VIRUSTOTAL_ENABLED: bool = False

    # LDAP (optional)
    LDAP_ENABLED: bool = False
    LDAP_SERVER: Optional[str] = None
    LDAP_BASE_DN: Optional[str] = None
    LDAP_BIND_DN: Optional[str] = None
    LDAP_BIND_PASSWORD: Optional[str] = None

    # Notifications
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "netaudit@localhost"
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None

    # Data retention (days; 0 keeps forever). Purged daily by the beat task `purge_old_data`.
    RETENTION_SCAN_DAYS: int = 180       # finished scans, their findings and raw nmap output
    RETENTION_CAPTURE_DAYS: int = 7      # packet captures (.pcap) may hold credentials/content
    RETENTION_DEVICE_DAYS: int = 365     # devices not seen since, with no remaining findings

    # Scan limits
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT_SECONDS: int = 3600

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
