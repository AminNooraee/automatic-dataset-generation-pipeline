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
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
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
from automatic_dataset_generation.database.postgresql import PostgreSQLAdapter

__all__ = [
    "ColumnInfo",
    "DatabaseAdapter",
    "DatabaseAdapterError",
    "DatabaseAdapterFactory",
    "DatabaseAdapterNotRegisteredError",
    "DatabaseConnectionError",
    "DatabaseConnectionSpec",
    "DatabaseEngine",
    "DatabaseObjectNotFoundError",
    "DatabaseOperationError",
    "DatabaseServerInfo",
    "PostgreSQLAdapter",
    "RelationshipInfo",
    "SampleResult",
    "TableDescription",
    "TableInfo",
    "UnsupportedDatabaseEngineError",
    "parse_connection_string",
]
