"""Public database connection interpretation API."""

from automatic_dataset_generation.database.connection import (
    DatabaseConnectionSpec,
    DatabaseEngine,
    parse_connection_string,
)
from automatic_dataset_generation.database.errors import (
    DatabaseConnectionError,
    UnsupportedDatabaseEngineError,
)

__all__ = [
    "DatabaseConnectionError",
    "DatabaseConnectionSpec",
    "DatabaseEngine",
    "UnsupportedDatabaseEngineError",
    "parse_connection_string",
]
