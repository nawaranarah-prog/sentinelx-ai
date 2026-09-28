from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULT_SECRET = "dev-insecure-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "SentinelX AI"

    database_url: str = Field(default="sqlite:///./sentinelx.db",
                              validation_alias=AliasChoices("DATABASE_URL", "POSTGRES_URL"))
    secret_key: str = INSECURE_DEFAULT_SECRET
    # Serverless platforms (Vercel sets VERCEL=1) may freeze a function after it responds, so uploads are
    # processed inside the request and long-running features (live simulation) are disabled.
    serverless: bool = Field(default=False, validation_alias=AliasChoices("SERVERLESS", "VERCEL"))
    auto_migrate: bool = False
    access_token_expire_minutes: int = 480
    cookie_secure: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    llm_provider: Literal["auto", "none", "gateway", "anthropic", "openai"] = "auto"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 90.0
    llm_max_tool_rounds: int = 10
    llm_refusal_fallback: bool = True

    max_upload_mb: int = 25
    max_upload_rows: int = 200_000
    rate_limit_auth_per_minute: int = 20
    rate_limit_ai_per_minute: int = 20
    rate_limit_upload_per_minute: int = 10

    allow_registration: bool = True
    ai_context_max_events: int = Field(default=120, ge=10, le=1000)
    ai_context_max_chars: int = Field(default=60_000, ge=5_000)

    @field_validator("database_url")
    @classmethod
    def _normalize_db_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            v = "postgresql://" + v[len("postgres://"):]
        if v.startswith("postgresql://"):
            v = "postgresql+psycopg://" + v[len("postgresql://"):]
        return v

    @model_validator(mode="after")
    def _serverless_sqlite_fallback(self):
        # Without a configured database a serverless filesystem is read-only except /tmp. Fall back to an
        # ephemeral SQLite file there; /api/system/health reports it as non-persistent.
        if self.serverless and self.database_url == "sqlite:///./sentinelx.db":
            self.database_url = "sqlite:////tmp/sentinelx.db"
        return self

    @property
    def database_is_ephemeral(self) -> bool:
        return self.serverless and self.database_url.startswith("sqlite")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")



@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.environment == "production" and settings.secret_key == INSECURE_DEFAULT_SECRET:
        raise RuntimeError("SECRET_KEY must be set to a strong random value in production")
    return settings
