"""Tests for typed runtime configuration and secret-safe behavior."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from automatic_dataset_generation.core.settings import AppSettings, RuntimeEnvironment

SETTING_ENVIRONMENT_VARIABLES = (
    "ADGP_ENVIRONMENT",
    "ADGP_LOG_LEVEL",
    "ADGP_DATABASE_CONNECTION_STRING",
    "ADGP_GATEWAY_API_KEY",
)


@pytest.fixture(autouse=True)
def clear_settings_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep settings tests independent from the invoking process environment."""
    for variable_name in SETTING_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable_name, raising=False)


def test_settings_have_safe_defaults() -> None:
    settings = AppSettings(_env_file=None)

    assert settings.environment is RuntimeEnvironment.DEVELOPMENT
    assert settings.log_level == "INFO"
    assert settings.database_connection_string is None
    assert settings.gateway_api_key is None


def test_settings_load_prefixed_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADGP_ENVIRONMENT", "test")
    monkeypatch.setenv("ADGP_LOG_LEVEL", "warning")

    settings = AppSettings(_env_file=None)

    assert settings.environment is RuntimeEnvironment.TEST
    assert settings.log_level == "WARNING"


def test_invalid_log_level_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADGP_LOG_LEVEL", "verbose")

    with pytest.raises(ValidationError, match="log_level must be one of"):
        AppSettings(_env_file=None)


def test_invalid_runtime_environment_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADGP_ENVIRONMENT", "banana")

    with pytest.raises(ValidationError):
        AppSettings(_env_file=None)


def test_empty_optional_secrets_are_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADGP_DATABASE_CONNECTION_STRING", "  ")
    monkeypatch.setenv("ADGP_GATEWAY_API_KEY", "")

    settings = AppSettings(_env_file=None)

    assert settings.database_connection_string is None
    assert settings.gateway_api_key is None


def test_secrets_do_not_appear_in_representations_or_safe_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_marker = "sensitive-database-marker"
    gateway_marker = "sensitive-gateway-marker"
    monkeypatch.setenv("ADGP_DATABASE_CONNECTION_STRING", database_marker)
    monkeypatch.setenv("ADGP_GATEWAY_API_KEY", gateway_marker)

    settings = AppSettings(_env_file=None)
    rendered_values = (
        repr(settings),
        str(settings),
        settings.model_dump_json(),
        str(settings.model_dump()),
    )

    assert all(database_marker not in rendered for rendered in rendered_values)
    assert all(gateway_marker not in rendered for rendered in rendered_values)
    assert settings.safe_summary() == {"environment": "development", "log_level": "INFO"}


def test_environment_variables_override_dotenv_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ADGP_ENVIRONMENT=staging\n"
        "ADGP_LOG_LEVEL=ERROR\n"
        "ADGP_DATABASE_CONNECTION_STRING=file-db-value\n",  # pragma: allowlist secret
        encoding="utf-8",
    )
    monkeypatch.setenv("ADGP_ENVIRONMENT", "test")
    monkeypatch.setenv("ADGP_LOG_LEVEL", "warning")
    monkeypatch.setenv("ADGP_DATABASE_CONNECTION_STRING", "os-db-value")

    settings = AppSettings(_env_file=env_file)

    assert settings.environment is RuntimeEnvironment.TEST
    assert settings.log_level == "WARNING"
    assert settings.database_connection_string is not None
    assert settings.database_connection_string.get_secret_value() == "os-db-value"


def test_settings_gateway_validation_and_host_parsing() -> None:
    """Verifies gateway URL security validation, JSON array host parsing, and safe summaries."""
    # JSON array parsing
    s1 = AppSettings(
        gateway_trusted_hosts='["localhost", "gateway.internal"]',
        _env_file=None,
    )
    assert s1.gateway_trusted_hosts == ("localhost", "gateway.internal")

    # Sequence parsing
    s2 = AppSettings(gateway_trusted_hosts=["127.0.0.1", "::1"], _env_file=None)
    assert s2.gateway_trusted_hosts == ("127.0.0.1", "::1")

    # Empty base url treated as unset
    s3 = AppSettings(gateway_base_url="   ", _env_file=None)
    assert s3.gateway_base_url is None
    summary = s3.safe_agent_summary()
    assert summary["gateway_base_url"] is None

    # Rejection of NUL byte
    with pytest.raises(ValidationError, match="must not contain NUL"):
        AppSettings(gateway_base_url="http://localhost\x00/v1", _env_file=None)

    # Rejection of invalid scheme
    with pytest.raises(ValidationError, match="scheme must be 'http' or 'https'"):
        AppSettings(gateway_base_url="ftp://localhost/v1", _env_file=None)

    # Rejection of missing hostname
    with pytest.raises(ValidationError, match="valid hostname"):
        AppSettings(gateway_base_url="http:///v1", _env_file=None)

    # Rejection of user credentials
    with pytest.raises(ValidationError, match="must not contain embedded user credentials"):
        AppSettings(
            gateway_base_url="http://user:pass@localhost:4000/v1",  # pragma: allowlist secret
            _env_file=None,
        )

    # Rejection of URL fragments
    with pytest.raises(ValidationError, match="must not contain URL fragments"):
        AppSettings(gateway_base_url="http://localhost:4000/v1#part", _env_file=None)

    # Rejection of plain HTTP on remote host
    with pytest.raises(ValidationError, match="Plaintext HTTP is only allowed for loopback hosts"):
        AppSettings(gateway_base_url="http://remote.host:4000/v1", _env_file=None)

    # Safe summary with port
    s_port = AppSettings(gateway_base_url="http://localhost:8080/v1/chat", _env_file=None)
    assert s_port.safe_agent_summary()["gateway_base_url"] == "http://localhost:8080"
