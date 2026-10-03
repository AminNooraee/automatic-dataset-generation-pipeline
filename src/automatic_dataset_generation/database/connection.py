"""Typed database connection-string parsing without network access."""

import re
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from automatic_dataset_generation.database.errors import (
    DatabaseConnectionError,
    UnsupportedDatabaseEngineError,
)

_DRIVER_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


class DatabaseEngine(StrEnum):
    """Normalized relational database engines supported by the parser."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"


class DatabaseConnectionSpec(BaseModel):
    """Immutable, secret-aware result of connection-string interpretation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    engine: DatabaseEngine
    driver: str | None = None
    raw_connection_string: SecretStr = Field(repr=False)

    def safe_summary(self) -> dict[str, str | None]:
        """Return only metadata approved for diagnostics."""
        return {
            "engine": self.engine.value,
            "driver": self.driver,
        }

    def __repr__(self) -> str:
        """Represent the specification without secret connection data."""
        return self._safe_representation()

    def __str__(self) -> str:
        """Render the specification without secret connection data."""
        return self._safe_representation()

    def _safe_representation(self) -> str:
        return f"{type(self).__name__}(engine={self.engine.value!r}, driver={self.driver!r})"


def parse_connection_string(connection_string: str | SecretStr) -> DatabaseConnectionSpec:
    """Interpret a database URI scheme without contacting the target database.

    The complete input is retained only as ``SecretStr``. Expected failures use generic,
    non-sensitive messages and never interpolate the supplied connection string.
    """
    raw_value = (
        connection_string.get_secret_value()
        if isinstance(connection_string, SecretStr)
        else connection_string
    )
    if not isinstance(raw_value, str):
        raise DatabaseConnectionError("Database connection string must be text")
    if not raw_value.strip():
        raise DatabaseConnectionError("Database connection string must not be empty")
    if raw_value != raw_value.strip():
        raise DatabaseConnectionError("Malformed database connection string")

    try:
        parsed = urlsplit(raw_value)
    except ValueError:
        raise DatabaseConnectionError("Malformed database connection string") from None

    scheme = parsed.scheme.casefold()
    if not scheme:
        raise DatabaseConnectionError("Database connection string must include a URI scheme")

    scheme_prefix, separator, _remainder = raw_value.partition("://")
    if not separator or scheme_prefix.casefold() != scheme:
        raise DatabaseConnectionError("Malformed database connection scheme")
    if scheme.count("+") > 1:
        raise DatabaseConnectionError("Malformed database connection scheme")

    engine_name, driver_separator, driver = scheme.partition("+")
    if driver_separator and not _DRIVER_PATTERN.fullmatch(driver):
        raise DatabaseConnectionError("Malformed database connection scheme")

    return DatabaseConnectionSpec(
        engine=_normalize_engine(engine_name),
        driver=driver if driver_separator else None,
        raw_connection_string=SecretStr(raw_value),
    )


def _normalize_engine(engine_name: str) -> DatabaseEngine:
    match engine_name:
        case "postgres" | "postgresql":
            return DatabaseEngine.POSTGRESQL
        case "mysql":
            return DatabaseEngine.MYSQL
        case "mariadb":
            return DatabaseEngine.MARIADB
        case "mssql" | "sqlserver":
            return DatabaseEngine.MSSQL
        case "oracle":
            return DatabaseEngine.ORACLE
        case "sqlite":
            return DatabaseEngine.SQLITE
        case _:
            raise UnsupportedDatabaseEngineError("Unsupported database engine")
