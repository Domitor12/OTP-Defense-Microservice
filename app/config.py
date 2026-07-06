"""
Centralized configuration via environment variables.
Uses pydantic-settings for validation and type coercion.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────
    app_env: str = Field(default="production", alias="APP_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")

    # ── PostgreSQL ───────────────────────────────────
    postgres_user: str = Field(alias="POSTGRES_USER")
    postgres_password: str = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(alias="POSTGRES_DB")
    postgres_host: str = Field(default="postgres", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    database_pool_size: int = Field(default=20, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=10, alias="DATABASE_MAX_OVERFLOW")

    # ── Redis ────────────────────────────────────────
    redis_host: str = Field(default="redis", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_password: str = Field(default="", alias="REDIS_PASSWORD")
    redis_db: int = Field(default=0, alias="REDIS_DB")

    # ── Rate Limit Thresholds ────────────────────────
    failed_login_window_seconds: int = Field(default=300, alias="FAILED_LOGIN_WINDOW_SECONDS")
    failed_login_max_attempts: int = Field(default=3, alias="FAILED_LOGIN_MAX_ATTEMPTS")
    otp_request_window_seconds: int = Field(default=600, alias="OTP_REQUEST_WINDOW_SECONDS")
    otp_request_max_attempts: int = Field(default=2, alias="OTP_REQUEST_MAX_ATTEMPTS")

    # ── Security ─────────────────────────────────────
    api_auth_token: str = Field(alias="API_AUTH_TOKEN")

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Used by Alembic migrations (which run synchronously)."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    return Settings()