from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULT_SECRET = "dev-insecure-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "SentinelX AI"

    database_url: str = "sqlite:///./sentinelx.db"
    secret_key: str = INSECURE_DEFAULT_SECRET
    access_token_expire_minutes: int = 480
    cookie_secure: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    llm_provider: Literal["none", "anthropic", "openai"] = "none"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 60.0
    llm_max_tool_rounds: int = 4
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

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def llm_configured(self) -> bool:
        return self.llm_provider != "none" and bool(self.llm_api_key)

    @property
    def effective_llm_model(self) -> str:
        if self.llm_model:
            return self.llm_model
        return {"anthropic": "claude-opus-5", "openai": "gpt-4o-mini"}.get(self.llm_provider, "")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.environment == "production" and settings.secret_key == INSECURE_DEFAULT_SECRET:
        raise RuntimeError("SECRET_KEY must be set to a strong random value in production")
    return settings
