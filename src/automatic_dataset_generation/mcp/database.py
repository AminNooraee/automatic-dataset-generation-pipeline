"""Safe MCP tool boundary for an injected database adapter."""

from __future__ import annotations

import base64
import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from typing import TypeVar
from uuid import UUID

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict

from automatic_dataset_generation.database import (
    DatabaseAdapter,
    DatabaseAdapterError,
    DatabaseObjectNotFoundError,
    DatabaseServerInfo,
    RelationshipInfo,
    TableDescription,
    TableInfo,
)

_MAX_POLICY_SAMPLE_ROWS = 1_000
_MAX_POLICY_COLUMNS = 1_024
_MAX_POLICY_DEPTH = 32
_MAX_POLICY_VALUES = 1_000_000
_T = TypeVar("_T")

type JSONValue = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None


@dataclass(frozen=True, slots=True)
class DatabaseToolPolicy:
    """Immutable MCP-level limits independent of an adapter's own hard limits."""

    max_sample_rows: int = 25
    max_sample_columns: int = 128
    max_container_depth: int = 8
    max_encoded_values: int = 10_000

    def __post_init__(self) -> None:
        _validate_policy_bound(
            self.max_sample_rows, "max_sample_rows", maximum=_MAX_POLICY_SAMPLE_ROWS
        )
        _validate_policy_bound(
            self.max_sample_columns, "max_sample_columns", maximum=_MAX_POLICY_COLUMNS
        )
        _validate_policy_bound(
            self.max_container_depth, "max_container_depth", maximum=_MAX_POLICY_DEPTH
        )
        _validate_policy_bound(
            self.max_encoded_values, "max_encoded_values", maximum=_MAX_POLICY_VALUES
        )


class SampleRowsResponse(BaseModel):
    """JSON-safe transport view of bounded, trusted raw database rows.

    Values are transport encoded, not sanitized. This output must pass through the future security
    and sanitization layer before it may be exposed to an LLM.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    schema_name: str
    table_name: str
    columns: tuple[str, ...]
    rows: tuple[tuple[JSONValue, ...], ...]
    row_count: int
    truncated: bool


class _TransportEncodingError(TypeError):
    """Internal signal for values that cannot cross the MCP JSON boundary safely."""


@dataclass(slots=True)
class _EncodingState:
    count: int = 0


class DatabaseToolService:
    """Stateless allowlisted tool service around a trusted, injected adapter."""

    __slots__ = ("_adapter", "_policy")

    def __init__(
        self,
        adapter: DatabaseAdapter,
        *,
        policy: DatabaseToolPolicy | None = None,
    ) -> None:
        if not isinstance(adapter, DatabaseAdapter):
            raise TypeError("adapter must implement DatabaseAdapter")
        self._adapter = adapter
        self._policy = policy or DatabaseToolPolicy()

    async def get_server_info(self) -> DatabaseServerInfo:
        """Return read-only database server metadata."""
        return await self._invoke(self._adapter.get_server_info)

    async def list_schemas(self) -> tuple[str, ...]:
        """List schemas visible through read-only database access."""
        return await self._invoke(self._adapter.list_schemas)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        """List read-only tables and views in one schema."""
        _validate_identifier(schema)
        return await self._invoke(lambda: self._adapter.list_tables(schema))

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        """Describe one table or view through read-only metadata."""
        _validate_identifier(schema)
        _validate_identifier(table)
        return await self._invoke(lambda: self._adapter.describe_table(schema, table))

    async def get_relationships(
        self,
        schema: str,
        table: str | None = None,
    ) -> tuple[RelationshipInfo, ...]:
        """Return read-only relationship metadata for a schema or table."""
        _validate_identifier(schema)
        if table is not None:
            _validate_identifier(table)
        return await self._invoke(lambda: self._adapter.get_relationships(schema, table))

    async def get_row_count(self, schema: str, table: str) -> int:
        """Return an exact read-only row count for one table or view."""
        _validate_identifier(schema)
        _validate_identifier(table)
        return await self._invoke(lambda: self._adapter.get_row_count(schema, table))

    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: list[str] | None = None,
    ) -> SampleRowsResponse:
        """Return bounded trusted raw rows with JSON-safe transport encoding, not sanitization."""
        _validate_identifier(schema)
        _validate_identifier(table)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self._policy.max_sample_rows
        ):
            raise ToolError("Invalid database tool input")
        if columns is not None:
            if not columns or len(columns) > self._policy.max_sample_columns:
                raise ToolError("Invalid database tool input")
            for column in columns:
                _validate_identifier(column)

        result = await self._invoke(
            lambda: self._adapter.sample_rows(
                schema,
                table,
                limit,
                tuple(columns) if columns is not None else None,
            )
        )
        if (
            result.row_count > self._policy.max_sample_rows
            or len(result.columns) > self._policy.max_sample_columns
        ):
            raise ToolError("Database tool result exceeds transport policy")

        state = _EncodingState()
        try:
            encoded_rows = tuple(
                tuple(_encode_value(value, self._policy, state, depth=0) for value in row)
                for row in result.rows
            )
        except _TransportEncodingError:
            raise ToolError("Database tool result is unavailable") from None

        return SampleRowsResponse(
            schema_name=result.schema_name,
            table_name=result.table_name,
            columns=result.columns,
            rows=encoded_rows,
            row_count=result.row_count,
            truncated=result.truncated,
        )

    async def _invoke(self, operation: Callable[[], Awaitable[_T]]) -> _T:
        try:
            return await operation()
        except DatabaseObjectNotFoundError:
            raise ToolError("Database object is unavailable") from None
        except DatabaseAdapterError:
            raise ToolError("Database tool operation failed") from None


def create_database_mcp(
    adapter: DatabaseAdapter,
    *,
    policy: DatabaseToolPolicy | None = None,
) -> FastMCP:
    """Create, but do not start, the seven-tool database MCP server."""
    service = DatabaseToolService(adapter, policy=policy)
    server = FastMCP(
        "automatic-dataset-generation-database",
        mask_error_details=True,
        strict_input_validation=True,
    )
    registrations = (
        (service.get_server_info, "get_server_info", "Return read-only database server metadata."),
        (service.list_schemas, "list_schemas", "List schemas visible to read-only access."),
        (service.list_tables, "list_tables", "List read-only tables and views in a schema."),
        (service.describe_table, "describe_table", "Describe a table or view read-only."),
        (
            service.get_relationships,
            "get_relationships",
            "Return read-only relationship metadata.",
        ),
        (service.get_row_count, "get_row_count", "Return an exact read-only row count."),
        (
            service.sample_rows,
            "sample_rows",
            "Return bounded trusted raw rows; values are not sanitized.",
        ),
    )
    for method, name, description in registrations:
        server.tool(method, name=name, description=description)
    return server


def _validate_identifier(value: object) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ToolError("Invalid database tool input")


def _validate_policy_bound(value: object, name: str, *, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer from 1 through {maximum}")


def _encode_value(
    value: object,
    policy: DatabaseToolPolicy,
    state: _EncodingState,
    *,
    depth: int,
) -> JSONValue:
    state.count += 1
    if state.count > policy.max_encoded_values or depth > policy.max_container_depth:
        raise _TransportEncodingError

    encoded: JSONValue
    if isinstance(value, (list, tuple)):
        encoded = _encode_sequence(value, policy, state, depth=depth)
    elif isinstance(value, Mapping):
        encoded = _encode_mapping(value, policy, state, depth=depth)
    else:
        encoded = _encode_scalar(value)
    return encoded


def _encode_scalar(value: object) -> JSONValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        encoded = base64.b64encode(bytes(value)).decode("ascii")
        return {"type": "bytes", "encoding": "base64", "value": encoded}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    return _encode_string_tagged_scalar(value)


def _encode_float(value: float) -> JSONValue:
    if math.isfinite(value):
        return value
    if math.isnan(value):
        label = "nan"
    elif value > 0:
        label = "positive_infinity"
    else:
        label = "negative_infinity"
    return {"type": "float", "value": label}


def _encode_string_tagged_scalar(value: object) -> JSONValue:
    if isinstance(value, datetime):
        return {"type": "datetime", "value": value.isoformat()}
    if isinstance(value, date):
        return {"type": "date", "value": value.isoformat()}
    if isinstance(value, time):
        return {"type": "time", "value": value.isoformat()}
    if isinstance(value, UUID):
        return {"type": "uuid", "value": str(value)}
    raise _TransportEncodingError


def _encode_sequence(
    value: list[object] | tuple[object, ...],
    policy: DatabaseToolPolicy,
    state: _EncodingState,
    *,
    depth: int,
) -> list[JSONValue]:
    return [_encode_value(item, policy, state, depth=depth + 1) for item in value]


def _encode_mapping(
    value: Mapping[str, object],
    policy: DatabaseToolPolicy,
    state: _EncodingState,
    *,
    depth: int,
) -> dict[str, JSONValue]:
    if not all(isinstance(key, str) for key in value):
        raise _TransportEncodingError
    return {key: _encode_value(item, policy, state, depth=depth + 1) for key, item in value.items()}
