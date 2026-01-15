from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Intentionally simple settings for an internal tool.

    Tradeoff: We prefer straightforward environment variables over a config service.
    """

    model_config = SettingsConfigDict(env_prefix="CCE_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://cce_user:cce_pass@localhost:5432/cce_db"
    app_name: str = "Continuous Compliance Engine"


settings = Settings()

