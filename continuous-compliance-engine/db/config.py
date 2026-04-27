from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Fix 1: removed env_prefix="CCE_" — was silently ignoring DATABASE_URL in .env
    # Fix 2: added simulate_drift as a typed field so pydantic-settings reads it from .env
    #         instead of relying on os.getenv() which doesn't read .env files
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./cce.db"
    simulate_drift: bool = False
    app_name: str = "Continuous Compliance Engine"


settings = Settings()
