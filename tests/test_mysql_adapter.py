"""Offline tests for the production MySQL adapter."""

from __future__ import annotations

from datetime import date
from typing import Any
from unittest.mock import AsyncMock

import asyncmy
import pytest
from asyncmy.errors import OperationalError

from automatic_dataset_generation.database import (
    DatabaseAdapterError,
    DatabaseAdapterFactory,
    DatabaseEngine,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
    MySQLAdapter,
    parse_connection_string,
)

MARKER = "synthetic-secret-marker"
EXPECTED_QUERY_CALLS = 3
DEFAULT_PORT = 3306
EXPECTED_COUNT = 7
EXPECTED_SAMPLE_ROWS = 2


class Cursor:
    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        names: tuple[str, ...] = (),
        fail_at: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.rows = rows
        # asyncmy returns PEP 249 seven-element tuples, with name at index zero.
        self.description = tuple((name, None, None, None, None, None, None) for name in names)
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.fail_at = fail_at
        self.failure = failure

    async def __aenter__(self) -> Cursor:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, query: str, params: tuple[object, ...] = ()) -> None:
        self.calls.append((query, params))
        if len(self.calls) == self.fail_at and self.failure is not None:
            raise self.failure

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows


class Connection:
    def __init__(
        self,
        cursor: Cursor,
        close_failure: Exception | None = None,
        local_close_failure: Exception | None = None,
    ) -> None:
        self._cursor = cursor
        self.closed = False
        self.close_failure = close_failure
        self.local_close_failure = local_close_failure
        self.graceful_close_calls = 0

    def cursor(self) -> Cursor:
        return self._cursor

    async def ensure_closed(self) -> None:
        self.graceful_close_calls += 1
        if self.close_failure:
            raise self.close_failure
        self.close()

    def close(self) -> None:
        self.closed = True
        if self.local_close_failure:
            raise self.local_close_failure


class Adapter(MySQLAdapter):
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
        uri or f"mysql://synthetic-user:{MARKER}@synthetic-host/synthetic-db"
    )


def application_call(cursor: Cursor) -> tuple[str, tuple[object, ...]]:
    assert len(cursor.calls) == EXPECTED_QUERY_CALLS
    assert cursor.calls[0] == ("SET SESSION TRANSACTION READ ONLY", ())
    assert cursor.calls[1] == ("SET SESSION max_execution_time = 10000", ())
    return cursor.calls[2]


@pytest.mark.parametrize(
    "uri",
    [
        "mysql://synthetic-user@synthetic-host/db",
        "mysql+asyncmy://synthetic-user@synthetic-host/db",
        "MYSQL+ASYNCMY://synthetic-user@synthetic-host/db",
    ],
)
def test_constructor_accepts_mysql_without_network(
    uri: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    connect = AsyncMock()
    monkeypatch.setattr(asyncmy, "connect", connect)
    adapter = MySQLAdapter(spec(uri))
    assert "synthetic-host" not in repr(adapter)
    assert MARKER not in str(adapter)
    connect.assert_not_called()


@pytest.mark.parametrize(
    "uri",
    [
        "postgresql://synthetic-user@host/db",
        "mariadb://synthetic-user@host/db",
        "mysql+aiomysql://synthetic-user@host/db",
        "mysql+pymysql://synthetic-user@host/db",
        "mysql+mysqlconnector://synthetic-user@host/db",
    ],
)
def test_wrong_engine_or_driver_rejected(uri: str) -> None:
    with pytest.raises(DatabaseAdapterError):
        MySQLAdapter(spec(uri))


@pytest.mark.parametrize("value", [True, False, 0, -1, float("inf"), float("nan"), "1"])
@pytest.mark.parametrize("field", ["connect_timeout", "statement_timeout"])
def test_timeout_validation(value: object, field: str) -> None:
    with pytest.raises(DatabaseAdapterError):
        MySQLAdapter(spec(), **{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "10"])
def test_sample_max_validation(value: object) -> None:
    with pytest.raises(DatabaseAdapterError):
        MySQLAdapter(spec(), max_sample_rows=value)  # type: ignore[arg-type]


def test_timeout_rejects_mysql_overflow() -> None:
    with pytest.raises(DatabaseAdapterError):
        MySQLAdapter(spec(), statement_timeout=4_294_967.296)


@pytest.mark.parametrize(
    "uri",
    [
        "mysql://synthetic-user@host",
        "mysql://host/db",
        "mysql://synthetic-user@host/",
        "mysql://synthetic-user@host:0/db",
        "mysql://synthetic-user@host:65536/db",
        "mysql://synthetic-user@host/db?bad=1",
    ],
)
def test_bad_connection_components_are_safe(uri: str) -> None:
    with pytest.raises(DatabaseAdapterError) as caught:
        MySQLAdapter(spec(uri))
    assert uri not in str(caught.value)
    assert caught.value.__suppress_context__ or caught.value.__context__ is None


@pytest.mark.asyncio
async def test_connect_decodes_uri_and_requests_autocommit(monkeypatch: pytest.MonkeyPatch) -> None:
    connect = AsyncMock(return_value=object())
    monkeypatch.setattr(asyncmy, "connect", connect)
    adapter = MySQLAdapter(spec("MYSQL+ASYNCMY://user%20name:pass%40word@[::1]:3307/db%20name"))
    await adapter._connect()
    assert connect.await_args is not None
    assert connect.await_args.kwargs == {
        "host": "::1",
        "port": 3307,
        "user": "user name",
        "password": "pass@word",  # pragma: allowlist secret
        "database": "db name",
        "connect_timeout": 5.0,
        "autocommit": True,
    }
    default = MySQLAdapter(spec("mysql://user@127.0.0.1/db"))
    await default._connect()
    assert connect.await_args is not None
    assert connect.await_args.kwargs["port"] == DEFAULT_PORT


@pytest.mark.asyncio
async def test_server_info_and_session_order() -> None:
    cursor = Cursor([("8.4", "app")])
    adapter = Adapter(spec(), cursors=[cursor])
    info = await adapter.get_server_info()
    assert info.engine is DatabaseEngine.MYSQL
    assert (info.version, info.database) == ("8.4", "app")
    assert application_call(cursor)[0] == "SELECT VERSION(), DATABASE()"
    assert adapter.connections[0].closed
    assert adapter.connections[0].graceful_close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("seconds", "ms"), [(10, 10000), (0.5, 500), (0.0004, 1)])
async def test_timeout_rounding(seconds: float, ms: int) -> None:
    cursor = Cursor([])
    await Adapter(spec(), cursors=[cursor], statement_timeout=seconds).list_schemas()
    assert cursor.calls[1][0] == f"SET SESSION max_execution_time = {ms}"


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_at", [1, 2, 3])
async def test_driver_error_fails_closed_redacts_and_closes(fail_at: int) -> None:
    cursor = Cursor([], fail_at=fail_at, failure=OperationalError(MARKER))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert len(cursor.calls) == fail_at
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert adapter.connections[0].closed
    assert adapter.connections[0].graceful_close_calls == 1


@pytest.mark.asyncio
async def test_programming_error_is_not_wrapped() -> None:
    cursor = Cursor([], fail_at=3, failure=ValueError("programmer failure"))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(ValueError, match="programmer failure"):
        await adapter.list_schemas()
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_connect_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncmy, "connect", AsyncMock(side_effect=OperationalError(MARKER)))
    with pytest.raises(DatabaseOperationError) as caught:
        await MySQLAdapter(spec()).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.asyncio
async def test_schemas_and_tables_have_catalog_filters_and_order() -> None:
    schemas = Cursor([("app",), ("billing",)])
    tables = Cursor([("events", "BASE TABLE"), ("report", "VIEW")])
    adapter = Adapter(spec(), cursors=[schemas, tables])
    assert await adapter.list_schemas() == ("app", "billing")
    query, _ = application_call(schemas)
    assert all(
        name in query for name in ("information_schema", "mysql", "performance_schema", "sys")
    )
    assert "ORDER BY SCHEMA_NAME" in query
    result = await adapter.list_tables("app")
    assert tuple((item.table_name, item.table_type) for item in result) == (
        ("events", "table"),
        ("report", "view"),
    )
    query, params = application_call(tables)
    assert "TABLE_TYPE IN ('BASE TABLE', 'VIEW')" in query
    assert "ORDER BY TABLE_NAME" in query
    assert params == ("app",)
    assert all(connection.closed for connection in adapter.connections)


@pytest.mark.asyncio
async def test_describe_columns_pk_and_missing_object() -> None:
    cursor = Cursor(
        [
            ("first", "int", "NO", 1),
            ("second", "int", "NO", 1),
            ("optional", "varchar(20)", "YES", 0),
        ]
    )
    adapter = Adapter(spec(), cursors=[cursor, Cursor([])])
    columns = (await adapter.describe_table("app", "events")).columns
    assert tuple(c.name for c in columns) == ("first", "second", "optional")
    assert tuple(c.nullable for c in columns) == (False, False, True)
    assert tuple(c.primary_key for c in columns) == (True, True, False)
    query, params = application_call(cursor)
    assert "INFORMATION_SCHEMA.STATISTICS" in query
    assert "pk.INDEX_NAME = 'PRIMARY'" in query
    assert "pk.TABLE_SCHEMA = c.TABLE_SCHEMA" in query
    assert "pk.TABLE_NAME = c.TABLE_NAME" in query
    assert "ORDER BY c.ORDINAL_POSITION" in query
    assert params == ("app", "events")
    with pytest.raises(DatabaseObjectNotFoundError) as caught:
        await adapter.describe_table("app", "secret_table")
    assert "secret_table" not in str(caught.value)


@pytest.mark.asyncio
async def test_relationship_scoping_and_composite_pairing() -> None:
    rows = [
        ("billing", "invoices", "a", "app", "orders", "y", "fk"),
        ("billing", "invoices", "b", "app", "orders", "x", "fk"),
    ]
    cursor = Cursor(rows)
    adapter = Adapter(spec(), cursors=[cursor, Cursor([])])
    relationships = await adapter.get_relationships("app", "orders")
    assert tuple((r.source_column, r.target_column) for r in relationships) == (
        ("a", "y"),
        ("b", "x"),
    )
    query, params = application_call(cursor)
    assert "k.REFERENCED_COLUMN_NAME" in query
    assert "k.ORDINAL_POSITION" in query
    assert params == ("app", "orders", "orders", "app", "orders", "app", "orders")
    assert "k.TABLE_SCHEMA = %s AND k.TABLE_NAME = %s" in query
    assert "k.REFERENCED_TABLE_SCHEMA = %s" in query
    assert "AND k.REFERENCED_TABLE_NAME = %s" in query
    await adapter.get_relationships("app")
    assert application_call(adapter.connections[1]._cursor)[1] == (
        "app",
        None,
        None,
        "app",
        None,
        "app",
        None,
    )


@pytest.mark.asyncio
async def test_exact_count_and_identifier_quoting() -> None:
    cursor = Cursor([(7,)])
    count = await Adapter(spec(), cursors=[cursor]).get_row_count(
        "weird schema", "danger`name; DROP TABLE users"
    )
    assert count == EXPECTED_COUNT
    assert application_call(cursor)[0] == (
        "SELECT COUNT(*) FROM `weird schema`.`danger``name; DROP TABLE users`"
    )


@pytest.mark.asyncio
async def test_sampling_is_bounded_uses_metadata_and_preserves_values() -> None:
    rows = [(1, date(2026, 1, 1)), (2, None), (3, "hidden")]
    cursor = Cursor(rows, ("select", "\u00e9`"))
    adapter = Adapter(spec(), cursors=[cursor], max_sample_rows=2)
    result = await adapter.sample_rows("weird schema", "t", 2, ("select", "\u00e9`"))
    assert result.rows == tuple(rows[:2])
    assert result.columns == ("select", "\u00e9`")
    assert result.row_count == EXPECTED_SAMPLE_ROWS
    assert result.truncated
    assert application_call(cursor) == (
        "SELECT `select`, `\u00e9``` FROM `weird schema`.`t` LIMIT %s",
        (3,),
    )
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_sampling_without_extra_row_and_all_columns() -> None:
    cursor = Cursor([(1,)], ("id",))
    result = await Adapter(spec(), cursors=[cursor]).sample_rows("app", "t", 2)
    assert result.rows == ((1,),)
    assert not result.truncated
    assert application_call(cursor) == ("SELECT * FROM `app`.`t` LIMIT %s", (3,))


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, 101, True, 1.5])
async def test_invalid_sampling_limit_fails_before_connect(limit: object) -> None:
    adapter = Adapter(spec(), cursors=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("app", "t", limit)  # type: ignore[arg-type]
    assert not adapter.connections


@pytest.mark.asyncio
@pytest.mark.parametrize("columns", [(), ("",), ("bad\x00name",)])
async def test_invalid_columns_fail_before_connect(columns: tuple[str, ...]) -> None:
    adapter = Adapter(spec(), cursors=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("app", "t", columns=columns)
    assert not adapter.connections


def test_no_generic_sql_and_factory_injection() -> None:
    forbidden = {
        "execute",
        "execute_sql",
        "query",
        "raw_query",
        "run_sql",
        "run_any_sql",
        "custom_sql",
    }
    assert forbidden.isdisjoint(dir(MySQLAdapter))
    factory = DatabaseAdapterFactory({DatabaseEngine.MYSQL: MySQLAdapter})
    assert isinstance(factory.create(spec()), MySQLAdapter)


@pytest.mark.asyncio
async def test_describe_access_denial_is_not_found_and_fails_closed() -> None:
    cursor = Cursor([], fail_at=3, failure=OperationalError(1142, MARKER))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(DatabaseObjectNotFoundError) as caught:
        await adapter.describe_table("app", "private")
    assert "private" not in str(caught.value)
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert len(cursor.calls) == EXPECTED_QUERY_CALLS
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_close_error_does_not_replace_result(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = Connection(Cursor([("8.4", "app")]), OperationalError(MARKER))
    adapter = MySQLAdapter(spec())
    monkeypatch.setattr(asyncmy, "connect", AsyncMock(return_value=connection))
    assert (await adapter.get_server_info()).version == "8.4"
    assert connection.closed
    assert connection.graceful_close_calls == 1


@pytest.mark.parametrize("seconds", [31_536_000, 31_536_000.0])
def test_connect_timeout_accepts_driver_maximum(seconds: float) -> None:
    adapter = MySQLAdapter(spec(), connect_timeout=seconds)
    assert adapter._connect_timeout == seconds


@pytest.mark.parametrize("seconds", [31_536_000.0001, 31_536_001])
def test_connect_timeout_rejects_above_driver_maximum(seconds: float) -> None:
    with pytest.raises(DatabaseAdapterError, match="connect_timeout exceeds") as caught:
        MySQLAdapter(spec(), connect_timeout=seconds)
    assert MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_graceful_close_failure_preserves_safe_operation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = Cursor([], fail_at=3, failure=OperationalError(MARKER))
    connection = Connection(cursor, OperationalError(MARKER), OperationalError(MARKER))
    monkeypatch.setattr(asyncmy, "connect", AsyncMock(return_value=connection))
    with pytest.raises(DatabaseOperationError) as caught:
        await MySQLAdapter(spec()).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert connection.graceful_close_calls == 1
    assert connection.closed
