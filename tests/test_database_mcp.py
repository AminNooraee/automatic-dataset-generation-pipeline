"""Tests for the safe database MCP tool boundary.

These tests exercise only the tool service, the JSON-safe transport encoder, and FastMCP's
in-process client/server. They use a fake ``DatabaseAdapter`` and perform no database access, no
network access, and open no real MCP transport.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from automatic_dataset_generation.database import (
    DatabaseAdapter,
    DatabaseAdapterError,
    DatabaseObjectNotFoundError,
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
    parse_connection_string,
)
from automatic_dataset_generation.mcp import (
    DatabaseToolPolicy,
    DatabaseToolService,
    SampleRowsResponse,
    create_database_mcp,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

EXPECTED_TOOL_NAMES = {
    "describe_table",
    "get_relationships",
    "get_row_count",
    "get_server_info",
    "list_schemas",
    "list_tables",
    "sample_rows",
}
GENERIC_SQL_TOOL_NAMES = {"execute", "execute_sql", "query", "raw_query", "run_any_sql", "run_sql"}
FORBIDDEN_TOOL_PARAMETERS = {
    "connection_string",
    "connection",
    "password",
    "api_key",
    "token",
    "secret",
    "credential",
}
LEAK_PROBE = "synthetic-phase2i-rotation-value"
ROW_COUNT = 12  # len("public") + len("events"), mirroring the fake get_row_count.


def _spec() -> Any:
    return parse_connection_string(f"postgresql://synthetic-user:{LEAK_PROBE}@host/database")


@dataclass
class FakeAdapter(DatabaseAdapter):
    """In-memory adapter that returns scripted values and records adapter calls.

    Call counts let tests assert that invalid tool input fails before reaching the adapter.
    """

    connection_spec: Any
    sample_result: SampleResult | None = None
    server_info: DatabaseServerInfo | None = None
    relationship_default_table: str = "events"
    raise_error: Exception | None = None
    adapter_calls: list[str] = field(default_factory=list)
    last_sample_limit: int | None = None
    last_sample_columns: tuple[str, ...] | None = None
    last_sample_target: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        DatabaseAdapter.__init__(self, self.connection_spec)

    async def get_server_info(self) -> DatabaseServerInfo:
        self.adapter_calls.append("get_server_info")
        if self.raise_error is not None:
            raise self.raise_error
        assert self.server_info is not None
        return self.server_info

    async def list_schemas(self) -> tuple[str, ...]:
        self.adapter_calls.append("list_schemas")
        if self.raise_error is not None:
            raise self.raise_error
        return ("public",)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        self.adapter_calls.append("list_tables")
        if self.raise_error is not None:
            raise self.raise_error
        return (TableInfo(schema_name=schema, table_name="events"),)

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        self.adapter_calls.append("describe_table")
        if self.raise_error is not None:
            raise self.raise_error
        return TableDescription(schema_name=schema, table_name=table, columns=())

    async def get_relationships(
        self,
        schema: str,
        table: str | None = None,
    ) -> tuple[RelationshipInfo, ...]:
        self.adapter_calls.append("get_relationships")
        if self.raise_error is not None:
            raise self.raise_error
        source = table or self.relationship_default_table
        return (
            RelationshipInfo(
                source_schema=schema,
                source_table=source,
                source_column="account_id",
                target_schema=schema,
                target_table="accounts",
                target_column="account_id",
            ),
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        self.adapter_calls.append("get_row_count")
        if self.raise_error is not None:
            raise self.raise_error
        return len(schema) + len(table)

    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: tuple[str, ...] | None = None,
    ) -> SampleResult:
        self.adapter_calls.append("sample_rows")
        self.last_sample_target = (schema, table)
        self.last_sample_limit = limit
        self.last_sample_columns = columns
        if self.raise_error is not None:
            raise self.raise_error
        assert self.sample_result is not None
        return self.sample_result

    def sample_result_for(
        self,
        values: Sequence[Any],
        *,
        row_count: int | None = None,
        truncated: bool = False,
    ) -> None:
        """Script a single-row sample result whose columns are generated from value count."""
        columns = tuple(f"column_{index}" for index in range(len(values)))
        count = row_count if row_count is not None else 1
        rows = (tuple(values),) * count
        self.sample_result = SampleResult(
            schema_name="public",
            table_name="events",
            columns=columns,
            rows=rows,
            row_count=count,
            truncated=truncated,
        )


def _service(
    adapter: FakeAdapter, *, policy: DatabaseToolPolicy | None = None
) -> DatabaseToolService:
    return DatabaseToolService(adapter, policy=policy)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_construction_performs_no_database_activity() -> None:
    adapter = FakeAdapter(_spec())

    _service(adapter)

    assert adapter.adapter_calls == []


def test_service_rejects_non_adapter_injection() -> None:
    with pytest.raises(TypeError):
        DatabaseToolService(object())  # type: ignore[arg-type]


def test_server_exposes_exactly_seven_allowlisted_tools() -> None:
    server = create_database_mcp(FakeAdapter(_spec()))

    async def scenario() -> set[str]:
        async with Client(server) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools}

    names = _run(scenario())

    assert names == EXPECTED_TOOL_NAMES
    assert names.isdisjoint(GENERIC_SQL_TOOL_NAMES)


def test_tool_schemas_expose_no_secret_fields() -> None:
    server = create_database_mcp(FakeAdapter(_spec()))

    async def scenario() -> set[str]:
        async with Client(server) as client:
            tools = await client.list_tools()
        return {key for tool in tools for key in (tool.input_schema.get("properties") or {})}

    properties = _run(scenario())

    assert properties.isdisjoint(FORBIDDEN_TOOL_PARAMETERS)


@pytest.mark.asyncio
async def test_get_server_info_delegates() -> None:
    adapter = FakeAdapter(_spec())
    adapter.server_info = DatabaseServerInfo(engine=adapter._connection_spec.engine, version="v1")

    result = await _service(adapter).get_server_info()

    assert result.version == "v1"
    assert adapter.adapter_calls == ["get_server_info"]


@pytest.mark.asyncio
async def test_list_schemas_delegates() -> None:
    adapter = FakeAdapter(_spec())

    assert await _service(adapter).list_schemas() == ("public",)
    assert adapter.adapter_calls == ["list_schemas"]


@pytest.mark.asyncio
async def test_list_tables_delegates() -> None:
    adapter = FakeAdapter(_spec())

    tables = await _service(adapter).list_tables("public")

    assert [table.table_name for table in tables] == ["events"]
    assert adapter.adapter_calls == ["list_tables"]


@pytest.mark.asyncio
async def test_describe_table_delegates() -> None:
    adapter = FakeAdapter(_spec())

    description = await _service(adapter).describe_table("public", "events")

    assert (description.schema_name, description.table_name) == ("public", "events")
    assert adapter.adapter_calls == ["describe_table"]


@pytest.mark.asyncio
async def test_get_relationships_delegates_without_table() -> None:
    adapter = FakeAdapter(_spec())

    relationships = await _service(adapter).get_relationships("public")

    assert relationships[0].source_table == adapter.relationship_default_table
    assert adapter.adapter_calls == ["get_relationships"]


@pytest.mark.asyncio
async def test_get_relationships_delegates_with_table() -> None:
    adapter = FakeAdapter(_spec())

    relationships = await _service(adapter).get_relationships("public", "events")

    assert relationships[0].source_table == "events"
    assert adapter.adapter_calls == ["get_relationships"]


@pytest.mark.asyncio
async def test_get_row_count_delegates() -> None:
    adapter = FakeAdapter(_spec())

    assert await _service(adapter).get_row_count("public", "events") == ROW_COUNT
    assert adapter.adapter_calls == ["get_row_count"]


@pytest.mark.asyncio
async def test_sample_rows_converts_columns_list_to_tuple_preserving_order() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1, 2])
    limit = 2

    await _service(adapter).sample_rows("public", "events", limit=limit, columns=["b", "a"])

    assert adapter.last_sample_columns == ("b", "a")
    assert adapter.last_sample_limit == limit
    assert adapter.last_sample_target == ("public", "events")


@pytest.mark.asyncio
async def test_sample_rows_allows_none_columns() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1])

    await _service(adapter).sample_rows("public", "events", limit=1)

    assert adapter.last_sample_columns is None


@pytest.mark.asyncio
async def test_sample_rows_accepts_limit_equal_to_policy_max() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1, 2])
    service = _service(adapter, policy=DatabaseToolPolicy(max_sample_rows=5))

    await service.sample_rows("public", "events", limit=5)

    assert adapter.adapter_calls == ["sample_rows"]
    assert adapter.last_sample_limit == 5  # noqa: PLR2004


@pytest.mark.asyncio
async def test_sample_rows_rejects_limit_above_policy_max() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1])
    service = _service(adapter, policy=DatabaseToolPolicy(max_sample_rows=3))

    with pytest.raises(ToolError):
        await service.sample_rows("public", "events", limit=4)

    assert adapter.adapter_calls == []


@pytest.mark.asyncio
async def test_sample_rows_rejects_bool_limit() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1])

    with pytest.raises(ToolError):
        await _service(adapter).sample_rows("public", "events", limit=True)

    assert adapter.adapter_calls == []


@pytest.mark.asyncio
async def test_sample_rows_rejects_limit_below_one() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1])

    with pytest.raises(ToolError):
        await _service(adapter).sample_rows("public", "events", limit=0)

    assert adapter.adapter_calls == []


@pytest.mark.asyncio
async def test_sample_rows_rejects_column_count_above_policy_max() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1])
    service = _service(adapter, policy=DatabaseToolPolicy(max_sample_columns=2))

    with pytest.raises(ToolError):
        await service.sample_rows("public", "events", limit=1, columns=["a", "b", "c"])

    assert adapter.adapter_calls == []


@pytest.mark.asyncio
async def test_sample_rows_rejects_empty_columns_list() -> None:
    adapter = FakeAdapter(_spec())

    with pytest.raises(ToolError):
        await _service(adapter).sample_rows("public", "events", limit=1, columns=[])

    assert adapter.adapter_calls == []


@pytest.mark.parametrize("schema", ["", "has\x00nul", 123, None])
@pytest.mark.asyncio
async def test_invalid_identifier_rejected_before_adapter(schema: object) -> None:
    adapter = FakeAdapter(_spec())
    service = _service(adapter)

    with pytest.raises(ToolError):
        await service.list_tables(schema)  # type: ignore[arg-type]

    assert adapter.adapter_calls == []


@pytest.mark.asyncio
async def test_adapter_error_translated_to_tool_error() -> None:
    adapter = FakeAdapter(_spec())
    adapter.raise_error = DatabaseAdapterError(f"boom {LEAK_PROBE}")
    service = _service(adapter)

    with pytest.raises(ToolError) as exc:
        await service.list_schemas()

    assert str(exc.value) == "Database tool operation failed"
    assert LEAK_PROBE not in str(exc.value)
    assert LEAK_PROBE not in repr(exc.value)


@pytest.mark.asyncio
async def test_object_not_found_translated_to_tool_error() -> None:
    adapter = FakeAdapter(_spec())
    adapter.raise_error = DatabaseObjectNotFoundError(f"missing {LEAK_PROBE}")
    service = _service(adapter)

    with pytest.raises(ToolError) as exc:
        await service.describe_table("public", "events")

    assert str(exc.value) == "Database object is unavailable"
    assert LEAK_PROBE not in str(exc.value)


def test_policy_rejects_out_of_range_bounds() -> None:
    with pytest.raises(ValueError, match="max_sample_rows must be an integer"):
        DatabaseToolPolicy(max_sample_rows=0)
    with pytest.raises(ValueError, match="max_sample_columns must be an integer"):
        DatabaseToolPolicy(max_sample_columns=10_25)
    with pytest.raises(ValueError, match="max_container_depth must be an integer"):
        DatabaseToolPolicy(max_container_depth=33)
    with pytest.raises(ValueError, match="max_encoded_values must be an integer"):
        DatabaseToolPolicy(max_encoded_values=1_000_001)


def test_policy_rejects_bool_bound() -> None:
    with pytest.raises(ValueError, match="max_sample_rows must be an integer"):
        DatabaseToolPolicy(max_sample_rows=True)


def test_policy_defaults_are_conservative() -> None:
    policy = DatabaseToolPolicy()

    # Assert the documented defaults verbatim; these are the contract, not arbitrary thresholds.
    assert policy.max_sample_rows == 25  # noqa: PLR2004
    assert policy.max_sample_columns == 128  # noqa: PLR2004
    assert policy.max_container_depth == 8  # noqa: PLR2004
    assert policy.max_encoded_values == 10_000  # noqa: PLR2004


@pytest.mark.asyncio
async def test_transport_policy_rejects_oversized_result() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1], row_count=6, truncated=True)
    service = _service(adapter, policy=DatabaseToolPolicy(max_sample_rows=5))

    with pytest.raises(ToolError, match="exceeds transport policy"):
        await service.sample_rows("public", "events", limit=5)


@pytest.mark.asyncio
async def test_sample_rows_preserves_result_metadata() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1, 2], truncated=True)
    response: SampleRowsResponse = await _service(adapter).sample_rows("public", "events", limit=2)

    assert response.schema_name == "public"
    assert response.table_name == "events"
    assert response.columns == ("column_0", "column_1")
    assert response.row_count == 1
    assert response.truncated is True


@pytest.mark.asyncio
async def test_sample_rows_does_not_mutate_source_result() -> None:
    adapter = FakeAdapter(_spec())
    original_row: list[object] = [1, "text", Decimal("2.5")]
    adapter.sample_result_for(original_row)
    original = adapter.sample_result
    assert original is not None

    await _service(adapter).sample_rows("public", "events", limit=1)

    assert list(original.rows[0]) == original_row
    assert original.rows[0][2] is original_row[2]


def test_encoder_handles_primitive_and_structured_types() -> None:
    adapter = FakeAdapter(_spec())
    nested_value = {"nested": "value", "list": [3]}
    adapter.sample_result_for([None, True, 5, 1.5, "text", [1, 2], nested_value])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0] == (
        None,
        True,
        5,
        1.5,
        "text",
        [1, 2],
        {"nested": "value", "list": [3]},
    )


def test_encoder_encodes_bytes_base64() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([b"\x00\x01\x02"])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0] == {"type": "bytes", "encoding": "base64", "value": "AAEC"}


def test_encoder_encodes_bytearray_and_memoryview() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([bytearray(b"ab"), memoryview(b"cd")])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0]["value"] == "YWI="
    assert response.rows[0][1]["value"] == "Y2Q="


def test_encoder_encodes_decimal() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([Decimal("3.14159")])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0] == {"type": "decimal", "value": "3.14159"}


def test_encoder_encodes_datetime_date_time() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for(
        [
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
            date(2026, 1, 2),
            time(1, 2, 3),
        ]
    )

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0] == {"type": "datetime", "value": "2026-01-02T03:04:05+00:00"}
    assert response.rows[0][1] == {"type": "date", "value": "2026-01-02"}
    assert response.rows[0][2] == {"type": "time", "value": "01:02:03"}


def test_encoder_encodes_uuid() -> None:
    adapter = FakeAdapter(_spec())
    target = UUID("12345678-1234-5678-1234-567812345678")
    adapter.sample_result_for([target])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0] == {"type": "uuid", "value": str(target)}


def test_encoder_encodes_non_finite_floats() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([float("nan"), float("inf"), float("-inf")])

    response = _run(_service(adapter).sample_rows("public", "events", limit=1))

    assert response.rows[0][0] == {"type": "float", "value": "nan"}
    assert response.rows[0][1] == {"type": "float", "value": "positive_infinity"}
    assert response.rows[0][2] == {"type": "float", "value": "negative_infinity"}


def test_encoder_rejects_unknown_object_safely() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([object()])

    with pytest.raises(ToolError, match="unavailable"):
        _run(_service(adapter).sample_rows("public", "events", limit=1))


def test_encoder_rejects_mapping_with_non_string_keys() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([{1: "value"}])

    with pytest.raises(ToolError, match="unavailable"):
        _run(_service(adapter).sample_rows("public", "events", limit=1))


def test_encoder_enforces_container_depth_bound() -> None:
    adapter = FakeAdapter(_spec())
    nested: list[object] = []
    for _ in range(9):
        nested = [nested]
    adapter.sample_result_for([nested])

    with pytest.raises(ToolError, match="unavailable"):
        _run(_service(adapter).sample_rows("public", "events", limit=1))


def test_encoder_enforces_total_element_bound() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for(list(range(12)))
    service = _service(adapter, policy=DatabaseToolPolicy(max_encoded_values=11))

    with pytest.raises(ToolError, match="unavailable"):
        _run(service.sample_rows("public", "events", limit=1))


def test_programming_exception_is_not_success_at_service_layer() -> None:
    adapter = FakeAdapter(_spec())
    adapter.raise_error = RuntimeError(f"buggy {LEAK_PROBE}")
    service = _service(adapter)

    with pytest.raises(RuntimeError):
        _run(service.list_schemas())


# --- In-process FastMCP integration -------------------------------------------


def test_in_process_client_reaches_fake_adapter_and_structured_result() -> None:
    adapter = FakeAdapter(_spec())
    adapter.sample_result_for([1, "two", Decimal("3.0"), b"four", float("nan")])
    server = create_database_mcp(adapter)

    async def scenario() -> tuple[str, ...]:
        async with Client(server) as client:
            result = await client.call_tool("sample_rows", {"schema": "public", "table": "events"})
        assert result.is_error is False
        structured = result.structured_content
        assert json.dumps(structured)  # round-trips as valid JSON
        assert structured["schema_name"] == "public"
        assert structured["rows"][0][0] == 1
        assert structured["rows"][0][3]["type"] == "bytes"
        assert structured["rows"][0][4] == {"type": "float", "value": "nan"}
        return tuple(adapter.adapter_calls)

    calls = _run(scenario())

    assert calls == ("sample_rows",)


def test_in_process_client_tools_are_exactly_seven() -> None:
    server = create_database_mcp(FakeAdapter(_spec()))

    async def scenario() -> set[str]:
        async with Client(server) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools}

    assert _run(scenario()) == EXPECTED_TOOL_NAMES


def test_in_process_client_tool_error_is_safe() -> None:
    adapter = FakeAdapter(_spec())
    adapter.raise_error = DatabaseObjectNotFoundError(f"gone {LEAK_PROBE}")
    server = create_database_mcp(adapter)

    async def scenario() -> str:
        async with Client(server) as client:
            with pytest.raises(ToolError) as exc:
                await client.call_tool("describe_table", {"schema": "public", "table": "events"})
            return str(exc.value)

    message = _run(scenario())

    assert message == "Database object is unavailable"
    assert LEAK_PROBE not in message
