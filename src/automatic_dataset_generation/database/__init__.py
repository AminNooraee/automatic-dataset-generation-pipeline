"""Public engine-neutral database-layer API."""

from automatic_dataset_generation.database.adapter import DatabaseAdapter
from automatic_dataset_generation.database.connection import (
    DatabaseConnectionSpec,
    DatabaseEngine,
    parse_connection_string,
)
from automatic_dataset_generation.database.errors import (
    DatabaseAdapterError,
    DatabaseAdapterNotRegisteredError,
    DatabaseConnectionError,
    UnsupportedDatabaseEngineError,
)
from automatic_dataset_generation.database.factory import DatabaseAdapterFactory
from automatic_dataset_generation.database.models import (
    ColumnInfo,
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
)

__all__ = [
    "ColumnInfo",
    "DatabaseAdapter",
    "DatabaseAdapterError",
    "DatabaseAdapterFactory",
    "DatabaseAdapterNotRegisteredError",
    "DatabaseConnectionError",
    "DatabaseConnectionSpec",
    "DatabaseEngine",
    "DatabaseServerInfo",
    "RelationshipInfo",
    "SampleResult",
    "TableDescription",
    "TableInfo",
    "UnsupportedDatabaseEngineError",
    "parse_connection_string",
]
