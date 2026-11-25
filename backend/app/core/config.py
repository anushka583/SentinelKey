
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelKey"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    database_url: str = "sqlite:///./sentinelkey.db"

    model_config = SettingsConfigDict(
        env_prefix="SENTINELKEY_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
