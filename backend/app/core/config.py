
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelKey"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    database_url: str = "sqlite:///./sentinelkey.db"
    auth_mode: Literal["development", "oidc"] = "development"
    jwt_issuer: str = "sentinelkey-development"
    jwt_audience: str = "sentinelkey-api"
    jwt_secret: SecretStr | None = None
    oidc_jwks_url: str | None = None
    detection_failed_auth_threshold: int = Field(default=5, ge=2, le=100)
    detection_failed_auth_window_seconds: int = Field(
        default=600, ge=1, le=86_400
    )
    detection_access_denied_threshold: int = Field(default=5, ge=2, le=100)
    detection_access_denied_window_seconds: int = Field(
        default=600, ge=1, le=86_400
    )
    event_metadata_max_bytes: int = Field(default=16_384, ge=256, le=1_048_576)

    model_config = SettingsConfigDict(
        env_prefix="SENTINELKEY_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
