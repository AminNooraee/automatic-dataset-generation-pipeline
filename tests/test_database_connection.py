"""Tests for safe database connection-string interpretation."""

from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError

from automatic_dataset_generation.database import (
    DatabaseConnectionError,
    DatabaseConnectionSpec,
    DatabaseEngine,
    UnsupportedDatabaseEngineError,
    parse_connection_string,
)


@pytest.mark.parametrize(
    ("connection_string", "expected_engine", "expected_driver"),
    [
        (
            "postgresql://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.POSTGRESQL,
            None,
        ),
        (
            "postgresql+asyncpg://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.POSTGRESQL,
            "asyncpg",
        ),
        (
            "postgres+psycopg://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.POSTGRESQL,
            "psycopg",
        ),
        (
            "mysql://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MYSQL,
            None,
        ),
        (
            "mysql+pymysql://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MYSQL,
            "pymysql",
        ),
        (
            "mariadb://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MARIADB,
            None,
        ),
        (
            "mssql://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MSSQL,
            None,
        ),
        (
            "mssql+pyodbc://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MSSQL,
            "pyodbc",
        ),
        (
            "sqlserver+pyodbc://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.MSSQL,
            "pyodbc",
        ),
        (
            "oracle://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.ORACLE,
            None,
        ),
        (
            "oracle+oracledb://user:password@db.example/internal",  # pragma: allowlist secret
            DatabaseEngine.ORACLE,
            "oracledb",
        ),
        ("sqlite:///temporary.db", DatabaseEngine.SQLITE, None),
    ],
)
def test_parse_supported_connection_strings(
    connection_string: str,
    expected_engine: DatabaseEngine,
    expected_driver: str | None,
) -> None:
    spec = parse_connection_string(connection_string)

    assert spec.engine is expected_engine
    assert spec.driver == expected_driver
    assert isinstance(spec.raw_connection_string, SecretStr)
    assert spec.raw_connection_string.get_secret_value() == connection_string


def test_parse_accepts_secret_string_input() -> None:
    connection_string = SecretStr("postgresql+asyncpg:///synthetic")

    spec = parse_connection_string(connection_string)

    assert spec.engine is DatabaseEngine.POSTGRESQL
    assert spec.driver == "asyncpg"
    assert spec.raw_connection_string.get_secret_value() == connection_string.get_secret_value()


def test_scheme_and_driver_are_normalized_case_insensitively() -> None:
    spec = parse_connection_string("POSTGRES+PSYCOPG:///synthetic")

    assert spec.engine is DatabaseEngine.POSTGRESQL
    assert spec.driver == "psycopg"


@pytest.mark.parametrize(
    ("connection_string", "expected_message"),
    [
        ("", "Database connection string must not be empty"),
        ("   ", "Database connection string must not be empty"),
        ("db.example/internal", "Database connection string must include a URI scheme"),
        ("postgresql:/internal", "Malformed database connection scheme"),
        ("postgresql+://db.example/internal", "Malformed database connection scheme"),
        (
            "postgresql+asyncpg+extra://db.example/internal",
            "Malformed database connection scheme",
        ),
        (" postgresql://db.example/internal", "Malformed database connection string"),
        ("postgresql://[invalid", "Malformed database connection string"),
    ],
)
def test_invalid_connection_strings_are_rejected_safely(
    connection_string: str,
    expected_message: str,
) -> None:
    with pytest.raises(DatabaseConnectionError) as error:
        parse_connection_string(connection_string)

    assert str(error.value) == expected_message
    input_marker = connection_string.strip()
    if input_marker:
        assert input_marker not in str(error.value)


def test_non_text_input_is_rejected_safely() -> None:
    with pytest.raises(DatabaseConnectionError, match="must be text"):
        parse_connection_string(cast("Any", None))


def test_unsupported_engine_error_does_not_disclose_input() -> None:
    marker = "synthetic-unknown-secret-marker"
    connection_string = f"mongodb://user:{marker}@db.example/internal"

    with pytest.raises(UnsupportedDatabaseEngineError) as error:
        parse_connection_string(connection_string)

    assert str(error.value) == "Unsupported database engine"
    assert marker not in str(error.value)
    assert marker not in repr(error.value)


def test_connection_spec_has_only_safe_diagnostic_representations() -> None:
    marker = "synthetic-password-marker"
    connection_string = f"postgresql+asyncpg://synthetic-user:{marker}@host/internal"

    spec = parse_connection_string(connection_string)
    rendered_values = (
        repr(spec),
        str(spec),
        str(spec.safe_summary()),
        spec.model_dump_json(),
        str(spec.model_dump()),
        str(spec.model_dump(mode="json")),
    )

    assert spec.safe_summary() == {"engine": "postgresql", "driver": "asyncpg"}
    assert repr(spec) == "DatabaseConnectionSpec(engine='postgresql', driver='asyncpg')"
    assert all(marker not in rendered for rendered in rendered_values)
    assert all("synthetic-user" not in rendered for rendered in rendered_values)
    assert all("host" not in rendered for rendered in rendered_values)
    assert all("internal" not in rendered for rendered in rendered_values)


def test_model_validation_error_hides_connection_input() -> None:
    marker = "synthetic-validation-secret-marker"
    payload: dict[str, Any] = {
        "engine": "unsupported",
        "raw_connection_string": f"postgresql://user:{marker}@host/internal",
    }

    with pytest.raises(ValidationError) as error:
        DatabaseConnectionSpec.model_validate(payload)

    assert marker not in str(error.value)
    assert marker not in repr(error.value)
