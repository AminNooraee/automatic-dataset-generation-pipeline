"""Typed, environment-backed application settings."""

from enum import StrEnum
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeEnvironment(StrEnum):
    """Supported deployment environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class AppSettings(BaseSettings):
    """Application configuration loaded exclusively from environment-style sources.

    Secret fields use Pydantic's ``SecretStr`` and are hidden from normal ``repr`` and string
    output. Diagnostic logging must use :meth:`safe_summary`, which returns only explicitly
    approved fields. Arbitrary serialization must not be assumed safe for logging.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ADGP_",
        extra="ignore",
        frozen=True,
        validate_default=True,
    )

    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    log_level: str = "INFO"
    database_connection_string: SecretStr | None = Field(default=None, repr=False)
    gateway_api_key: SecretStr | None = Field(default=None, repr=False)

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        """Normalize and validate the configured log level."""
        normalized = value.strip().upper()
        allowed_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if normalized not in allowed_levels:
            allowed = ", ".join(sorted(allowed_levels))
            raise ValueError(f"log_level must be one of: {allowed}")
        return normalized

    @field_validator("database_connection_string", "gateway_api_key", mode="before")
    @classmethod
    def empty_secret_is_unset(cls, value: Any) -> Any:
        """Treat an empty environment variable as an absent optional secret."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def safe_summary(self) -> dict[str, str]:
        """Return non-sensitive settings suitable for diagnostics and structured logs."""
        return {
            "environment": self.environment.value,
            "log_level": self.log_level,
        }
