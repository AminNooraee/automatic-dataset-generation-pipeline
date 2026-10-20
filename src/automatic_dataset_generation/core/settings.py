import contextlib
import json
import urllib.parse
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
    gateway_base_url: str | None = Field(default=None)
    gateway_model_alias: str = Field(default="qwen-2.5-72b-instruct")
    gateway_timeout_seconds: float = Field(default=30.0, gt=0)
    gateway_connect_timeout_seconds: float | None = Field(default=10.0, gt=0)
    gateway_max_retries: int = Field(default=1, ge=0, le=5)
    gateway_trusted_hosts: tuple[str, ...] = Field(
        default=("localhost", "127.0.0.1", "::1", "gateway.internal", "litellm.internal")
    )
    agent_request_limit: int = Field(default=15, gt=0, le=100)
    agent_tool_calls_limit: int = Field(default=30, gt=0, le=200)
    agent_max_result_size: int = Field(default=50_000, gt=0, le=500_000)
    agent_total_tokens_limit: int | None = Field(default=100_000, ge=1)
    agent_output_tokens_limit: int | None = Field(default=16_384, ge=1)
    agent_parallel_tool_calls: bool = Field(default=False)

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

    @field_validator("gateway_base_url", mode="before")
    @classmethod
    def empty_base_url_is_unset(cls, value: Any) -> Any:
        """Treat empty or whitespace-only gateway URL as None."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("gateway_base_url")
    @classmethod
    def validate_gateway_base_url(cls, value: str | None) -> str | None:
        """Ensure gateway URL is a valid, secret-free HTTP(S) endpoint."""
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            return None
        if "\x00" in trimmed:
            raise ValueError("gateway_base_url must not contain NUL bytes")

        parsed = urllib.parse.urlsplit(trimmed)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("gateway_base_url scheme must be 'http' or 'https'")
        if not parsed.hostname:
            raise ValueError("gateway_base_url must include a valid hostname")
        if parsed.username or parsed.password:
            raise ValueError(
                "gateway_base_url must not contain embedded user credentials; use gateway_api_key"
            )
        if parsed.query:
            raise ValueError("gateway_base_url must not contain query parameters")
        if parsed.fragment:
            raise ValueError("gateway_base_url must not contain URL fragments")

        normalized_host = parsed.hostname.rstrip(".").lower()
        loopback_hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
        if parsed.scheme == "http" and normalized_host not in loopback_hosts:
            msg = (
                "Plaintext HTTP is only allowed for loopback hosts ('localhost', '127.0.0.1', "
                "'::1'); remote gateway endpoints must use HTTPS"
            )
            raise ValueError(msg)
        return trimmed

    @field_validator("gateway_trusted_hosts", mode="before")
    @classmethod
    def parse_trusted_hosts(cls, value: Any) -> tuple[str, ...]:
        """Parse trusted hosts from sequence, JSON array, or comma-separated string."""
        hosts: tuple[str, ...]
        if isinstance(value, str):
            trimmed = value.strip()
            if not trimmed:
                raise ValueError("gateway_trusted_hosts must be a non-empty sequence of hostnames")
            if trimmed.startswith("[") and trimmed.endswith("]"):
                with contextlib.suppress(json.JSONDecodeError, ValueError):
                    parsed = json.loads(trimmed)
                    if isinstance(parsed, list):
                        hosts = tuple(
                            str(h).strip().rstrip(".").lower() for h in parsed if str(h).strip()
                        )
                        if not hosts:
                            raise ValueError(
                                "gateway_trusted_hosts must be a non-empty sequence of hostnames"
                            )
                        return hosts
            hosts = tuple(h.strip().rstrip(".").lower() for h in trimmed.split(",") if h.strip())
        elif isinstance(value, (list, tuple, set)):
            hosts = tuple(str(h).strip().rstrip(".").lower() for h in value if str(h).strip())
        else:
            hosts = ()

        if not hosts:
            raise ValueError("gateway_trusted_hosts must be a non-empty sequence of hostnames")
        return hosts

    def validate_gateway_host_trusted(self) -> None:
        """Validate that gateway_base_url host belongs to gateway_trusted_hosts allowlist."""
        if not self.gateway_base_url:
            return
        if not self.gateway_trusted_hosts:
            raise ValueError(
                "gateway_trusted_hosts must not be empty when gateway_base_url is configured"
            )

        parsed = urllib.parse.urlsplit(self.gateway_base_url)
        host = (parsed.hostname or "").rstrip(".").lower()
        trusted = {h.rstrip(".").lower() for h in self.gateway_trusted_hosts}
        if host not in trusted:
            msg = f"gateway_base_url host {host!r} is not in trusted allowlist: {sorted(trusted)}"
            raise ValueError(msg)

    def safe_summary(self) -> dict[str, str]:
        """Return non-sensitive settings suitable for diagnostics and structured logs."""
        return {
            "environment": self.environment.value,
            "log_level": self.log_level,
        }

    def safe_agent_summary(self) -> dict[str, Any]:
        """Return non-sensitive agent and gateway configuration for diagnostics."""
        safe_url: str | None = None
        if self.gateway_base_url:
            parsed = urllib.parse.urlsplit(self.gateway_base_url)
            port_part = f":{parsed.port}" if parsed.port is not None else ""
            safe_url = f"{parsed.scheme}://{parsed.hostname}{port_part}"

        return {
            "environment": self.environment.value,
            "log_level": self.log_level,
            "gateway_base_url": safe_url,
            "gateway_model_alias": self.gateway_model_alias,
            "gateway_timeout_seconds": self.gateway_timeout_seconds,
            "gateway_connect_timeout_seconds": self.gateway_connect_timeout_seconds,
            "gateway_max_retries": self.gateway_max_retries,
            "agent_request_limit": self.agent_request_limit,
            "agent_tool_calls_limit": self.agent_tool_calls_limit,
            "agent_max_result_size": self.agent_max_result_size,
            "agent_total_tokens_limit": self.agent_total_tokens_limit,
            "agent_output_tokens_limit": self.agent_output_tokens_limit,
            "agent_parallel_tool_calls": self.agent_parallel_tool_calls,
            "has_gateway_api_key": self.gateway_api_key is not None,
        }
