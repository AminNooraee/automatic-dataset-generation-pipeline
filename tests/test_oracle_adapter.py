"""Focused offline tests for the production Oracle adapter."""

from __future__ import annotations

import socket
from datetime import date
from typing import Any
from unittest.mock import AsyncMock

import oracledb
import pytest

from automatic_dataset_generation.database import (
    DatabaseAdapterError,
    DatabaseAdapterFactory,
    DatabaseEngine,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
    OracleAdapter,
    parse_connection_string,
)

MARKER = "synthetic-secret-marker"
EXPECTED_COUNT = 7
EXPECTED_QUERY_CALLS = 2
EXPECTED_SAMPLE_ROWS = 2


class Column:
    def __init__(self, name: str) -> None:
        self.name = name


class Cursor:
    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        names: tuple[str, ...] = (),
        *,
        fail_at: int | None = None,
        failure: Exception | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.rows = rows
        self.description = tuple(Column(name) for name in names)
        self.calls: list[tuple[str, object]] = []
        self.fail_at = fail_at
        self.failure = failure
        self.events = events if events is not None else []
        self.closed = False

    async def execute(self, query: str, params: object = None) -> None:
        self.calls.append((query, params))
        self.events.append(f"execute:{query}")
        if len(self.calls) == self.fail_at and self.failure is not None:
            raise self.failure

    async def fetchall(self) -> list[tuple[Any, ...]]:
        self.events.append("fetchall")
        return self.rows

    def close(self) -> None:
        self.events.append("cursor_close")
        self.closed = True


class Connection:
    def __init__(
        self,
        cursor: Cursor,
        *,
        rollback_failure: Exception | None = None,
        close_failure: Exception | None = None,
    ) -> None:
        self._cursor = cursor
        self.events = cursor.events
        self._autocommit = True
        self._call_timeout = 0
        self.rollback_failure = rollback_failure
        self.close_failure = close_failure
        self.rollback_calls = 0
        self.closed = False

    @property
    def autocommit(self) -> bool:
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self.events.append(f"autocommit:{value}")
        self._autocommit = value

    @property
    def call_timeout(self) -> int:
        return self._call_timeout

    @call_timeout.setter
    def call_timeout(self, value: int) -> None:
        self.events.append(f"call_timeout:{value}")
        self._call_timeout = value

    def cursor(self) -> Cursor:
        self.events.append("cursor")
        return self._cursor

    async def rollback(self) -> None:
        self.events.append("rollback")
        self.rollback_calls += 1
        if self.rollback_failure is not None:
            raise self.rollback_failure

    async def close(self) -> None:
        self.events.append("connection_close")
        self.closed = True
        if self.close_failure is not None:
            raise self.close_failure


class Adapter(OracleAdapter):
    def __init__(self, *args: Any, cursors: list[Cursor], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cursors = cursors
        self.connections: list[Connection] = []

    async def _connect(self) -> Any:
        connection = Connection(self.cursors.pop(0))
        self.connections.append(connection)
        return connection


def spec(uri: str | None = None) -> Any:
    return parse_connection_string(
        uri or f"oracle://synthetic-user:{MARKER}@synthetic-host/ORCLPDB1"
    )


def application_call(cursor: Cursor) -> tuple[str, object]:
    assert cursor.calls[0] == ("SET TRANSACTION READ ONLY", None)
    assert len(cursor.calls) == EXPECTED_QUERY_CALLS
    return cursor.calls[1]


def test_constructor_accepts_supported_schemes_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = AsyncMock()
    monkeypatch.setattr(oracledb, "connect_async", connect)
    for uri in (
        "oracle://synthetic-user@synthetic-host/ORCLPDB1",
        "oracle+oracledb://synthetic-user@synthetic-host/ORCLPDB1",
        "ORACLE+ORACLEDB://synthetic-user@synthetic-host/ORCLPDB1",
    ):
        adapter = OracleAdapter(spec(uri))
        assert "synthetic-host" not in repr(adapter)
    connect.assert_not_called()


def test_wrong_engine_or_driver_rejected() -> None:
    for uri in ("mysql://user@host/db", "oracle+cx-oracle://user@host/service"):
        with pytest.raises(DatabaseAdapterError):
            OracleAdapter(spec(uri))


def test_constructor_rejects_unsafe_configuration() -> None:
    for field, value in (
        ("connect_timeout", True),
        ("statement_timeout", float("inf")),
        ("max_sample_rows", 0),
    ):
        with pytest.raises(DatabaseAdapterError):
            OracleAdapter(spec(), **{field: value})  # type: ignore[arg-type]


def test_constructor_rejects_timeout_upper_bounds() -> None:
    with pytest.raises(DatabaseAdapterError):
        OracleAdapter(spec(), connect_timeout=31_536_001)
    with pytest.raises(DatabaseAdapterError):
        OracleAdapter(spec(), statement_timeout=4_294_968.0)


def test_invalid_uri_components_are_rejected_safely() -> None:
    for uri in (
        "oracle://user@host",
        "oracle://host/service",
        "oracle://user@host:bad/service",
        "oracle://user@host/service?unsafe=1",
    ):
        with pytest.raises(DatabaseAdapterError) as caught:
            OracleAdapter(spec(uri))
        assert uri not in str(caught.value)


@pytest.mark.asyncio
async def test_connect_uses_decoded_keyword_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    connect = AsyncMock(return_value=object())
    monkeypatch.setattr(oracledb, "connect_async", connect)
    adapter = OracleAdapter(spec("ORACLE+ORACLEDB://user%20name:pass%40word@[::1]:1522/SVC%20NAME"))
    await adapter._connect()
    assert connect.await_args is not None
    assert connect.await_args.args == ()
    assert connect.await_args.kwargs == {
        "user": "user name",
        "password": "pass@word",  # pragma: allowlist secret
        "host": "::1",
        "port": 1522,
        "service_name": "SVC NAME",
        "tcp_connect_timeout": 5.0,
    }


@pytest.mark.asyncio
async def test_native_async_lifecycle_and_read_only_first() -> None:
    events: list[str] = []
    cursor = Cursor([("26.0", "ORCLPDB1")], events=events)
    info = await Adapter(spec(), cursors=[cursor]).get_server_info()
    assert (info.engine, info.version, info.database) == (
        DatabaseEngine.ORACLE,
        "26.0",
        "ORCLPDB1",
    )
    assert events[0:4] == [
        "autocommit:False",
        "call_timeout:10000",
        "cursor",
        "execute:SET TRANSACTION READ ONLY",
    ]
    assert events[-3:] == ["rollback", "cursor_close", "connection_close"]


@pytest.mark.asyncio
async def test_call_timeout_is_ceil_milliseconds() -> None:
    for seconds, milliseconds in ((10, 10000), (0.5, 500), (0.0004, 1)):
        cursor = Cursor([])
        adapter = Adapter(spec(), cursors=[cursor], statement_timeout=seconds)
        await adapter.list_schemas()
        assert adapter.connections[0].call_timeout == milliseconds


@pytest.mark.asyncio
async def test_read_only_failure_is_fail_closed_redacted_and_cleaned_up() -> None:
    cursor = Cursor([], fail_at=1, failure=oracledb.DatabaseError(MARKER))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert len(cursor.calls) == 1
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_list_catalog_queries_are_visible_and_deterministic() -> None:
    schemas = Cursor([("APP",), ("BILLING",)])
    tables = Cursor([("EVENTS", "table"), ("REPORT", "view")])
    adapter = Adapter(spec(), cursors=[schemas, tables])
    assert await adapter.list_schemas() == ("APP", "BILLING")
    assert tuple(t.table_type for t in await adapter.list_tables("APP")) == ("table", "view")
    schema_sql, _ = application_call(schemas)
    table_sql, params = application_call(tables)
    assert "oracle_maintained = 'N'" in schema_sql
    assert "all_tables" in schema_sql
    assert "all_views" in schema_sql
    assert "UNION ALL" in table_sql
    assert "ORDER BY object_name" in table_sql
    assert params == {"owner": "APP"}


@pytest.mark.asyncio
async def test_describe_table_formats_columns_and_composite_pk() -> None:
    cursor = Cursor(
        [
            ("A", "NUMBER", "N", 22, 10, 0, 0, None, 1),
            ("B", "NUMBER", "N", 22, 10, 0, 0, None, 1),
            ("NOTE", "VARCHAR2", "Y", 40, None, None, 40, "C", 0),
        ]
    )
    description = await Adapter(spec(), cursors=[cursor]).describe_table("APP", "EVENTS")
    assert tuple(column.data_type for column in description.columns) == (
        "NUMBER(10,0)",
        "NUMBER(10,0)",
        "VARCHAR2(40 CHAR)",
    )
    assert tuple(column.primary_key for column in description.columns) == (True, True, False)
    query, params = application_call(cursor)
    assert "all_tab_columns" in query
    assert "pk.constraint_type = 'P'" in query
    assert "pcc.owner = pk.owner" in query
    assert "ORDER BY c.column_id" in query
    assert params == {"owner": "APP", "table_name": "EVENTS"}


@pytest.mark.asyncio
async def test_describe_table_renders_remaining_declared_types() -> None:
    cursor = Cursor(
        [
            ("F", "FLOAT", "N", 126, 24, None, None, None, 0),
            ("R", "RAW", "N", 32, None, None, None, None, 0),
            ("N", "NUMBER", "N", 22, 22, None, None, None, 0),
            ("B", "VARCHAR2", "N", 100, None, None, 100, "B", 0),
            ("D", "DATE", "N", 7, None, None, None, None, 0),
        ]
    )
    description = await Adapter(spec(), cursors=[cursor]).describe_table("APP", "TYPES")
    assert tuple(column.data_type for column in description.columns) == (
        "FLOAT(24)",
        "RAW(32)",
        "NUMBER(22)",
        "VARCHAR2(100 BYTE)",
        "DATE",
    )


class _ErrorInfo:
    def __init__(self, code: int) -> None:
        self.code = code


@pytest.mark.asyncio
async def test_describe_table_classifies_not_found_or_inaccessible_codes() -> None:
    for code in (942, 1031):
        cursor = Cursor([], fail_at=2, failure=oracledb.DatabaseError(_ErrorInfo(code)))
        with pytest.raises(DatabaseObjectNotFoundError) as caught:
            await Adapter(spec(), cursors=[cursor]).describe_table("APP", "MISSING")
        assert "MISSING" not in str(caught.value)
        assert caught.value.__suppress_context__


@pytest.mark.asyncio
async def test_describe_table_does_not_classify_non_database_driver_error() -> None:
    # A non-database driver error carrying a not-found code must be a generic
    # operation failure, never misread as a missing object.
    cursor = Cursor([], fail_at=2, failure=oracledb.InterfaceError(_ErrorInfo(942)))
    with pytest.raises(DatabaseOperationError):
        await Adapter(spec(), cursors=[cursor]).describe_table("APP", "MISSING")


@pytest.mark.asyncio
async def test_missing_description_is_generic() -> None:
    adapter = Adapter(spec(), cursors=[Cursor([])])
    with pytest.raises(DatabaseObjectNotFoundError) as caught:
        await adapter.describe_table("APP", "SECRET_TABLE")
    assert "SECRET_TABLE" not in str(caught.value)


@pytest.mark.asyncio
async def test_relationships_pair_composite_columns_and_include_inbound_cross_schema() -> None:
    cursor = Cursor(
        [
            ("BILLING", "INVOICES", "A", "APP", "ORDERS", "Y", "FK_INVOICE"),
            ("BILLING", "INVOICES", "B", "APP", "ORDERS", "X", "FK_INVOICE"),
        ]
    )
    relationships = await Adapter(spec(), cursors=[cursor]).get_relationships("APP", "ORDERS")
    assert tuple((r.source_column, r.target_column) for r in relationships) == (
        ("A", "Y"),
        ("B", "X"),
    )
    assert all(r.source_schema == "BILLING" for r in relationships)
    query, params = application_call(cursor)
    assert "target.owner = src.r_owner" in query
    assert "target_col.position = src_col.position" in query
    assert "target.owner = :schema AND target.table_name = :table_name" in query
    assert "src_col.position" in query
    assert params == {"schema": "APP", "table_name": "ORDERS"}


@pytest.mark.asyncio
async def test_relationships_without_table_scope_source_schema() -> None:
    cursor = Cursor([])
    await Adapter(spec(), cursors=[cursor]).get_relationships("APP")
    query, params = application_call(cursor)
    assert "src.owner = :schema AND :table_name IS NULL" in query
    assert params == {"schema": "APP", "table_name": None}


@pytest.mark.asyncio
async def test_exact_count_escapes_identifiers() -> None:
    cursor = Cursor([(EXPECTED_COUNT,)])
    count = await Adapter(spec(), cursors=[cursor]).get_row_count(
        "Odd Schema", 'weird"name; DROP TABLE x'
    )
    assert count == EXPECTED_COUNT
    assert application_call(cursor) == (
        'SELECT COUNT(*) FROM "Odd Schema"."weird""name; DROP TABLE x"',
        None,
    )


@pytest.mark.asyncio
async def test_sampling_fetches_limit_plus_one_and_preserves_values() -> None:
    rows = [(1, date(2026, 1, 1)), (2, None), (3, "hidden")]
    cursor = Cursor(rows, ("select", 'odd"column'))
    result = await Adapter(spec(), cursors=[cursor], max_sample_rows=2).sample_rows(
        "Odd Schema", "T", 2, ("select", 'odd"column')
    )
    assert result.rows == tuple(rows[:2])
    assert result.columns == ("select", 'odd"column')
    assert result.row_count == EXPECTED_SAMPLE_ROWS
    assert result.truncated
    assert application_call(cursor) == (
        'SELECT "select", "odd""column" FROM "Odd Schema"."T" FETCH FIRST 3 ROWS ONLY',
        None,
    )


@pytest.mark.asyncio
async def test_invalid_sampling_input_fails_before_connect() -> None:
    adapter = Adapter(spec(), cursors=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("APP", "T", limit=True)
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("APP", "T", columns=())
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("APP", "T", columns=("",))
    assert not adapter.connections


@pytest.mark.asyncio
async def test_driver_error_redacted_but_programming_error_propagates() -> None:
    driver = Cursor([], fail_at=2, failure=oracledb.DatabaseError(MARKER))
    interface = Cursor([], fail_at=2, failure=oracledb.InterfaceError(MARKER))
    programmer = Cursor([], fail_at=2, failure=ValueError("programmer failure"))
    adapter = Adapter(spec(), cursors=[driver, interface, programmer])
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert MARKER not in str(caught.value)
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert MARKER not in str(caught.value)
    with pytest.raises(ValueError, match="programmer failure"):
        await adapter.list_schemas()
    assert all(connection.closed for connection in adapter.connections)


@pytest.mark.asyncio
async def test_connect_transport_failure_is_redacted_domain_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PRODUCTION FIX REQUIRED: an OSError raised while connecting must be
    translated to a redacted domain error, not escape the adapter.

    python-oracledb Thin propagates the raw socket/OSError (e.g. a getaddrinfo
    DNS failure) that is NOT an oracledb.DatabaseError, so today it bypasses the
    ``except oracledb.DatabaseError`` boundary and leaks both the failure and any
    driver-embedded detail to the caller.
    """
    connect = AsyncMock(side_effect=socket.gaierror(MARKER))
    monkeypatch.setattr(oracledb, "connect_async", connect)
    adapter = OracleAdapter(spec())
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert "Oracle operation 'list_schemas' failed" in str(caught.value)
    assert MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_cleanup_failures_do_not_replace_safe_primary_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = Cursor([], fail_at=2, failure=oracledb.DatabaseError(MARKER))
    cleanup_error = oracledb.DatabaseError(MARKER)
    connection = Connection(cursor, rollback_failure=cleanup_error, close_failure=cleanup_error)
    adapter = OracleAdapter(spec())
    monkeypatch.setattr(oracledb, "connect_async", AsyncMock(return_value=connection))
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert MARKER not in str(caught.value)
    assert cursor.closed
    assert connection.closed


def test_public_export_factory_and_no_generic_sql_api() -> None:
    forbidden = {
        "execute",
        "execute_sql",
        "query",
        "raw_query",
        "run_sql",
        "run_any_sql",
        "custom_sql",
    }
    assert forbidden.isdisjoint(dir(OracleAdapter))
    factory = DatabaseAdapterFactory({DatabaseEngine.ORACLE: OracleAdapter})
    assert isinstance(factory.create(spec()), OracleAdapter)
