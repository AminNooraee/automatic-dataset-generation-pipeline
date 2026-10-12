"""Offline tests for the production Microsoft SQL Server adapter."""

from __future__ import annotations

from datetime import date
from typing import Any
from unittest.mock import Mock, patch

import mssql_python
import pytest
from mssql_python import OperationalError

from automatic_dataset_generation.database import (
    DatabaseAdapterError,
    DatabaseAdapterFactory,
    DatabaseEngine,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
    MSSQLAdapter,
    parse_connection_string,
)
from automatic_dataset_generation.database.mssql import (
    _format_sql_server_type,
    _quote_identifier,
)

MARKER = "synthetic-secret-marker"
DEFAULT_PORT = 1433
EXPECTED_COUNT = 7
EXPECTED_SAMPLE_ROWS = 2


class Cursor:
    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        names: tuple[str, ...] = (),
        fail_at: int | None = None,
        failure: Exception | None = None,
        close_failure: Exception | None = None,
    ) -> None:
        self.rows = rows
        # PEP 249 seven-element tuples, with name at index zero.
        self.description = tuple((name, None, None, None, None, None, None) for name in names)
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.closed = False
        self.fail_at = fail_at
        self.failure = failure
        self.close_failure = close_failure

    def execute(self, operation: str, *parameters: object) -> None:
        # Mirror mssql-python: a single tuple/list/dict arg is unwrapped for binding.
        if len(parameters) == 1 and isinstance(parameters[0], (tuple, list, dict)):
            parameters = parameters[0]  # type: ignore[assignment]
        self.calls.append((operation, parameters))
        if len(self.calls) == self.fail_at and self.failure is not None:
            raise self.failure

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows

    def close(self) -> None:
        self.closed = True
        if self.close_failure:
            raise self.close_failure


class Connection:
    def __init__(
        self,
        cursor: Cursor,
        timeout_failure: Exception | None = None,
        close_failure: Exception | None = None,
    ) -> None:
        self._cursor = cursor
        self.timeout: int | None = None
        self.timeout_failure = timeout_failure
        self.close_failure = close_failure
        self.closed = False
        self.cursor_calls = 0

    def cursor(self) -> Cursor:
        self.cursor_calls += 1
        if self.timeout is None:
            raise AssertionError("connection.timeout must be set before cursor()")
        return self._cursor

    def close(self) -> None:
        self.closed = True
        if self.close_failure:
            raise self.close_failure


class Adapter(MSSQLAdapter):
    def __init__(self, *args: Any, cursors: list[Cursor], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cursors = cursors
        self.connections: list[Connection] = []

    def _connect(self) -> Any:
        connection = Connection(self.cursors.pop(0))
        self.connections.append(connection)
        return connection


def spec(uri: str | None = None) -> Any:
    return parse_connection_string(
        uri or f"mssql://synthetic-user:{MARKER}@synthetic-host/synthetic-db"
    )


def application_call(cursor: Cursor) -> tuple[str, tuple[object, ...]]:
    # mssql-python has exactly one statement per operation (no session setup queries).
    assert len(cursor.calls) == 1
    return cursor.calls[0]


@pytest.mark.parametrize(
    "uri",
    [
        "mssql://synthetic-user@synthetic-host/db",
        "sqlserver://synthetic-user@synthetic-host/db",
        "mssql+mssql-python://synthetic-user@synthetic-host/db",
        "sqlserver+mssql-python://synthetic-user@synthetic-host/db",
        "MSSQL+MSSQL-PYTHON://synthetic-user@synthetic-host/db",
    ],
)
def test_constructor_accepts_mssql_without_network(
    uri: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mssql_python, "connect", Mock())
    adapter = MSSQLAdapter(spec(uri))
    assert "synthetic-host" not in repr(adapter)
    assert MARKER not in str(adapter)


@pytest.mark.parametrize(
    "uri",
    [
        "postgresql://synthetic-user@host/db",
        "mysql://synthetic-user@host/db",
        "mariadb://synthetic-user@host/db",
        "mssql+aioodbc://synthetic-user@host/db",
        "mssql+pyodbc://synthetic-user@host/db",
        "mssql+pymssql://synthetic-user@host/db",
    ],
)
def test_wrong_engine_or_driver_rejected(uri: str) -> None:
    with pytest.raises(DatabaseAdapterError):
        MSSQLAdapter(spec(uri))


@pytest.mark.parametrize("value", [True, False, 0, -1, float("inf"), float("nan"), "1"])
@pytest.mark.parametrize("field", ["connect_timeout", "statement_timeout"])
def test_timeout_validation(value: object, field: str) -> None:
    with pytest.raises(DatabaseAdapterError):
        MSSQLAdapter(spec(), **{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "10"])
def test_sample_max_validation(value: object) -> None:
    with pytest.raises(DatabaseAdapterError):
        MSSQLAdapter(spec(), max_sample_rows=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("seconds", [31_536_000.0001, 31_536_001])
def test_statement_timeout_rejects_above_maximum(seconds: float) -> None:
    with pytest.raises(DatabaseAdapterError, match="statement_timeout exceeds") as caught:
        MSSQLAdapter(spec(), statement_timeout=seconds)
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize("seconds", [31_536_000, 31_536_000.0])
def test_connect_timeout_accepts_maximum(seconds: float) -> None:
    adapter = MSSQLAdapter(spec(), connect_timeout=seconds)
    assert adapter._login_timeout == seconds


@pytest.mark.parametrize("seconds", [31_536_000.0001, 31_536_001])
def test_connect_timeout_rejects_above_maximum(seconds: float) -> None:
    with pytest.raises(DatabaseAdapterError, match="connect_timeout exceeds") as caught:
        MSSQLAdapter(spec(), connect_timeout=seconds)
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize(
    "uri",
    [
        "mssql://synthetic-user@host",
        "mssql://host/db",
        "mssql://synthetic-user@host/",
        "mssql://synthetic-user@host:0/db",
        "mssql://synthetic-user@host:65536/db",
        "mssql://synthetic-user@host:abc/db",
        "mssql://synthetic-user@host/db?bad=1",
        "mssql://synthetic-user@host/db#frag",
    ],
)
def test_bad_connection_components_are_safe(uri: str) -> None:
    with pytest.raises(DatabaseAdapterError) as caught:
        MSSQLAdapter(spec(uri))
    assert uri not in str(caught.value)
    assert caught.value.__suppress_context__ or caught.value.__context__ is None


@pytest.mark.parametrize(
    "host_fragment",
    ["host;extra", "host,extra", "host\\instance", "host\x00x", "host name", " host"],
)
def test_endpoint_control_chars_rejected_safely(host_fragment: str) -> None:
    with pytest.raises(DatabaseAdapterError) as caught:
        MSSQLAdapter(spec(f"mssql://synthetic-user@{host_fragment}/db"))
    assert host_fragment not in str(caught.value)
    assert caught.value.__context__ is None


def test_nul_database_rejected_safely() -> None:
    with pytest.raises(DatabaseAdapterError) as caught:
        MSSQLAdapter(spec("mssql://synthetic-user@host/db%00x"))
    assert MARKER not in str(caught.value)
    assert caught.value.__context__ is None


def test_connect_kwargs_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    connect = Mock()
    monkeypatch.setattr(mssql_python, "connect", connect)
    adapter = MSSQLAdapter(spec("MSSQL://user%20name:pass%40word@[::1]:1499/db%20name"))
    # Exercise _connect directly: dynamic values and the security config must be kwargs.
    adapter._connect()
    assert connect.call_args.kwargs == {
        "autocommit": True,
        "timeout": 5,
        "encrypt": "yes",
        "trustservercertificate": "no",
        "applicationintent": "readonly",
        "server": "[::1]:1499",
        "uid": "user name",
        "pwd": "pass@word",  # pragma: allowlist secret
        "database": "db name",
    }
    # Default port is 1433.
    MSSQLAdapter(spec("mssql://user@127.0.0.1/db"))._connect()
    assert connect.call_args.kwargs["server"] == "127.0.0.1,1433"


@pytest.mark.asyncio
async def test_server_info_and_no_fake_read_only() -> None:
    cursor = Cursor([("15.0.2000", "app")])
    adapter = Adapter(spec(), cursors=[cursor])
    info = await adapter.get_server_info()
    assert info.engine is DatabaseEngine.MSSQL
    assert (info.version, info.database) == ("15.0.2000", "app")
    query, _ = application_call(cursor)
    assert "SERVERPROPERTY" in query
    assert "DB_NAME()" in query
    # No PostgreSQL/MySQL-style session read-only statement is issued.
    assert "READ ONLY" not in " ".join(c[0] for c in cursor.calls)
    assert adapter.connections[0].closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(10, 10), (10.0, 10), (0.5, 1), (0.0004, 1), (31_536_000, 31_536_000)],
)
async def test_statement_timeout_uses_ceil_seconds(seconds: float, expected: int) -> None:
    cursor = Cursor([])
    adapter = Adapter(spec(), cursors=[cursor], statement_timeout=seconds)
    await adapter.list_schemas()
    assert adapter.connections[0].timeout == expected


@pytest.mark.asyncio
async def test_timeout_set_before_cursor_creation() -> None:
    class RecordingConnection(Connection):
        def __init__(self, cursor: Cursor) -> None:
            super().__init__(cursor)
            self.order: list[str] = []

        def __setattr__(self, name: str, value: object) -> None:
            super().__setattr__(name, value)
            if name == "timeout" and hasattr(self, "order"):
                self.order.append("timeout")

        def cursor(self) -> Cursor:
            if hasattr(self, "order"):
                self.order.append("cursor")
            return super().cursor()

    adapter = Adapter(spec(), cursors=[Cursor([])])
    conn = RecordingConnection(Cursor([]))
    adapter.cursors = []
    adapter.connections = [conn]

    def fake_connect() -> Any:
        return conn

    with patch.object(adapter, "_connect", fake_connect):
        await adapter.list_schemas()
    assert conn.order.index("timeout") < conn.order.index("cursor")


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_at", [1])
async def test_driver_error_fails_closed_redacts_and_closes(fail_at: int) -> None:
    cursor = Cursor([], fail_at=fail_at, failure=OperationalError(MARKER, MARKER))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_programming_error_is_not_wrapped() -> None:
    cursor = Cursor([], fail_at=1, failure=ValueError("programmer failure"))
    adapter = Adapter(spec(), cursors=[cursor])
    with pytest.raises(ValueError, match="programmer failure"):
        await adapter.list_schemas()
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_connect_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mssql_python,
        "connect",
        Mock(side_effect=OperationalError(MARKER, MARKER)),
    )
    with pytest.raises(DatabaseOperationError) as caught:
        await MSSQLAdapter(spec()).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.asyncio
async def test_schemas_and_tables_filters_and_order() -> None:
    schemas = Cursor([("app",), ("billing",)])
    adapter = Adapter(spec(), cursors=[schemas])
    assert await adapter.list_schemas() == ("app", "billing")
    query, _ = application_call(schemas)
    assert "INFORMATION_SCHEMA" in query
    assert "'sys'" in query
    assert "HAS_PERMS_BY_NAME" in query
    assert "ORDER BY s.name" in query

    tables = Cursor([("events", "U"), ("report", "V")])
    adapter2 = Adapter(spec(), cursors=[tables])
    result = await adapter2.list_tables("app")
    assert tuple((item.table_name, item.table_type) for item in result) == (
        ("events", "table"),
        ("report", "view"),
    )
    query, params = application_call(tables)
    assert "o.type IN ('U', 'V')" in query
    assert "is_ms_shipped = 0" in query
    assert "ORDER BY o.name" in query
    assert params == ("app",)


@pytest.mark.asyncio
async def test_describe_columns_pk_and_missing_object() -> None:
    # (name, type, is_nullable, max_length, precision, scale, is_pk)
    cursor = Cursor(
        [
            ("first", "int", 0, 4, 10, 0, 1),
            ("second", "int", 0, 4, 10, 0, 1),
            ("optional", "varchar", 1, 20, 0, 0, 0),
        ],
        ("name", "type", "nullable", "max_length", "precision", "scale", "pk"),
    )
    adapter = Adapter(spec(), cursors=[cursor, Cursor([])])
    columns = (await adapter.describe_table("app", "events")).columns
    assert tuple(c.name for c in columns) == ("first", "second", "optional")
    assert tuple(c.nullable for c in columns) == (False, False, True)
    assert tuple(c.primary_key for c in columns) == (True, True, False)
    assert columns[2].data_type == "varchar(20)"
    query, params = application_call(cursor)
    assert "sys.indexes" in query
    assert "i.is_primary_key = 1" in query
    assert "ORDER BY c.column_id" in query
    assert params == ("app", "events")
    with pytest.raises(DatabaseObjectNotFoundError) as caught:
        await adapter.describe_table("app", "secret_table")
    assert "secret_table" not in str(caught.value)


@pytest.mark.asyncio
async def test_describe_temporal_and_view_are_describable() -> None:
    # Temporal (system-versioned) tables are type 'U' and must be describable.
    cursor = Cursor(
        [
            ("id", "bigint", 0, 8, 19, 0, 1),
            ("valid_from", "datetime2", 1, 8, 0, 7, 0),
        ]
    )
    adapter = Adapter(spec(), cursors=[cursor])
    description = await adapter.describe_table("app", "audit_log")
    assert tuple(c.name for c in description.columns) == ("id", "valid_from")
    assert description.columns[1].data_type == "datetime2(7)"
    query, _ = application_call(cursor)
    assert "o.type IN ('U', 'V')" in query


@pytest.mark.asyncio
async def test_describe_emits_case_when_exists_not_bare_exists() -> None:
    cursor = Cursor([("c", "int", 0, 4, 10, 0, 1)], ("name",))
    await Adapter(spec(), cursors=[cursor]).describe_table("app", "t")
    query, _ = application_call(cursor)
    assert "CASE" in query
    assert "WHEN EXISTS (" in query
    assert "THEN CAST(1 AS bit)" in query
    assert "ELSE CAST(0 AS bit)" in query
    # A bare EXISTS(...) must not be projected directly in the SELECT list; the only EXISTS is the
    # one guarded by the CASE WHEN above.
    assert query.count("EXISTS") == 1


@pytest.mark.asyncio
async def test_describe_uses_user_type_id_join_without_duplicating_columns() -> None:
    # Four same-typed columns: a join on system_type_id would fan out (one row per sys.types match),
    # whereas the user_type_id identity join returns exactly one row per physical column.
    cursor = Cursor(
        [
            ("a", "varchar", 0, 50, 0, 0, 1),
            ("b", "varchar", 0, 50, 0, 0, 0),
            ("c", "varchar", 0, 50, 0, 0, 0),
            ("d", "varchar", 0, 50, 0, 0, 0),
        ],
        ("name", "type", "nullable", "max_length", "precision", "scale", "pk"),
    )
    columns = (await Adapter(spec(), cursors=[cursor]).describe_table("app", "t")).columns
    assert tuple(c.name for c in columns) == ("a", "b", "c", "d")
    query, _ = application_call(cursor)
    assert "JOIN sys.types AS t ON t.user_type_id = c.user_type_id" in query
    assert "system_type_id" not in query


@pytest.mark.asyncio
async def test_describe_alias_and_udt_types_are_deterministic() -> None:
    # Alias and user-defined types join to exactly one sys.types row each (user_type_id), and their
    # names are rendered verbatim rather than resolved to an (incorrect) system type.
    cursor = Cursor(
        [
            ("m", "money_alias", 0, 8, 19, 4, 0),
            ("x", "custom_money", 0, 8, 19, 4, 0),
        ],
        ("name", "type", "nullable", "max_length", "precision", "scale", "pk"),
    )
    description = await Adapter(spec(), cursors=[cursor]).describe_table("app", "t")
    assert tuple(c.data_type for c in description.columns) == ("money_alias", "custom_money")
    assert tuple(c.primary_key for c in description.columns) == (False, False)


@pytest.mark.asyncio
async def test_permission_queries_use_quotename_and_equals_one() -> None:
    # Every permission check must use the documented QUOTENAME(schema) + N'.' + QUOTENAME(object)
    # pattern (supporting punctuation/spaces/brackets/dots) and must be compared with = 1, since
    # HAS_PERMS_BY_NAME returns int (1/0/NULL), not a predicate.
    schemas = Cursor([("app",)])
    tables = Cursor([("t", "U")])
    describe = Cursor([("c", "int", 0, 4, 10, 0, 1)])
    relationships = Cursor([])
    adapter = Adapter(spec(), cursors=[schemas, tables, describe, relationships])
    await adapter.list_schemas()
    await adapter.list_tables("app")
    await adapter.describe_table("app", "t")
    await adapter.get_relationships("app")
    for cursor in (schemas, tables, describe, relationships):
        query, _ = application_call(cursor)
        assert "HAS_PERMS_BY_NAME(" in query
        assert "QUOTENAME(" in query
        assert "SCHEMA_NAME(" not in query
        assert query.count("HAS_PERMS_BY_NAME(") == query.count(") = 1")
    assert "QUOTENAME(ss.name) + N'.' + QUOTENAME(st.name)" in application_call(relationships)[0]


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
    assert "sys.foreign_key_columns" in query
    assert "fkc.parent_column_id" in query
    assert "fkc.referenced_column_id" in query
    assert params == ("app", "orders", "orders", "app", "orders", "app", "orders")
    assert "ss.name = ? AND st.name = ?" in query
    assert "rs.name = ? AND rt.name = ?" in query
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
async def test_relationships_exclude_same_table_name_in_other_schema() -> None:
    cursor = Cursor([])
    adapter = Adapter(spec(), cursors=[cursor])
    assert await adapter.get_relationships("dbo", "orders") == ()
    assert application_call(cursor)[1] == (
        "dbo",
        "orders",
        "orders",
        "dbo",
        "orders",
        "dbo",
        "orders",
    )


@pytest.mark.asyncio
async def test_exact_count_big_and_identifier_quoting() -> None:
    cursor = Cursor([(7,)])
    count = await Adapter(spec(), cursors=[cursor]).get_row_count(
        "weird schema", "danger]name]; DROP TABLE users--"
    )
    assert count == EXPECTED_COUNT
    assert application_call(cursor)[0] == (
        "SELECT COUNT_BIG(*) FROM [weird schema].[danger]]name]]; DROP TABLE users--]"
    )


@pytest.mark.asyncio
async def test_identifier_quoting_variants() -> None:
    cases = [
        ("orders", "[orders]"),
        ("with space", "[with space]"),
        ("unicode_é", "[unicode_é]"),
        ("]", "[]]]"),
        ("select", "[select]"),
    ]
    for raw, expected in cases:
        cursor = Cursor([(1,)])
        await Adapter(spec(), cursors=[cursor]).get_row_count("app", raw)
        # Expected SQL literal for an assertion, not a query sent to a database.
        assert application_call(cursor)[0] == f"SELECT COUNT_BIG(*) FROM [app].{expected}"  # noqa: S608


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "bad\x00name"])
async def test_identifier_rejects_empty_and_nul(value: str) -> None:
    adapter = Adapter(spec(), cursors=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.get_row_count("app", value)
    assert not adapter.connections


def test_identifier_quoting_helper_rejects_bad_input() -> None:
    assert _quote_identifier("a]b") == "[a]]b]"
    for bad in ("", "bad\x00name"):
        with pytest.raises(DatabaseAdapterError):
            _quote_identifier(bad)


def test_endpoint_control_char_helper() -> None:
    for ok in ("host", "::1", "127.0.0.1", "myhost"):
        assert MSSQLAdapter._has_endpoint_control_chars(ok) is False
    for bad in ("host;extra", "host,x", "host\\inst", "a b", " h", "a b", "\x00", "host "):
        assert MSSQLAdapter._has_endpoint_control_chars(bad) is True


def test_sql_server_type_formatting() -> None:
    assert _format_sql_server_type("int", 4, 10, 0) == "int"
    assert _format_sql_server_type("varchar", 20, 0, 0) == "varchar(20)"
    assert _format_sql_server_type("nvarchar", 40, 0, 0) == "nvarchar(20)"
    assert _format_sql_server_type("varchar", -1, 0, 0) == "varchar(max)"
    assert _format_sql_server_type("decimal", 5, 18, 2) == "decimal(18,2)"
    assert _format_sql_server_type("numeric", 5, 10, 0) == "numeric(10,0)"
    assert _format_sql_server_type("datetime2", 8, 0, 7) == "datetime2(7)"
    assert _format_sql_server_type("datetime", 8, 0, 0) == "datetime"


@pytest.mark.asyncio
async def test_sampling_uses_top_and_preserves_values() -> None:
    rows = [(1, date(2026, 1, 1)), (2, None), (3, "hidden")]
    cursor = Cursor(rows, ("select", "é]"))
    adapter = Adapter(spec(), cursors=[cursor], max_sample_rows=2)
    result = await adapter.sample_rows("weird schema", "t", 2, ("select", "é]"))
    assert result.rows == tuple(rows[:2])
    assert result.columns == ("select", "é]")
    assert result.row_count == EXPECTED_SAMPLE_ROWS
    assert result.truncated
    assert application_call(cursor) == (
        "SELECT TOP 3 [select], [é]]] FROM [weird schema].[t]",
        (),
    )
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_sampling_without_extra_row_and_all_columns() -> None:
    cursor = Cursor([(1,)], ("id",))
    result = await Adapter(spec(), cursors=[cursor]).sample_rows("app", "t", 2)
    assert result.rows == ((1,),)
    assert not result.truncated
    assert application_call(cursor) == ("SELECT TOP 3 * FROM [app].[t]", ())


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
    assert forbidden.isdisjoint(dir(MSSQLAdapter))
    factory = DatabaseAdapterFactory({DatabaseEngine.MSSQL: MSSQLAdapter})
    assert isinstance(factory.create(spec()), MSSQLAdapter)


@pytest.mark.asyncio
async def test_close_error_does_not_replace_result(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = Cursor([("15.0", "app")])
    connection = Connection(cursor, close_failure=OperationalError(MARKER, MARKER))
    adapter = MSSQLAdapter(spec())
    monkeypatch.setattr(mssql_python, "connect", Mock(return_value=connection))
    assert (await adapter.get_server_info()).version == "15.0"
    assert connection.closed


@pytest.mark.asyncio
async def test_graceful_close_failure_preserves_safe_operation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = Cursor([], fail_at=1, failure=OperationalError(MARKER, MARKER))
    connection = Connection(cursor, close_failure=OperationalError(MARKER, MARKER))
    monkeypatch.setattr(mssql_python, "connect", Mock(return_value=connection))
    with pytest.raises(DatabaseOperationError) as caught:
        await MSSQLAdapter(spec()).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert connection.closed


@pytest.mark.asyncio
async def test_query_timeout_config_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadTimeoutConnection(Connection):
        _attr_started = False

        def __setattr__(self, name: str, value: object) -> None:
            if name == "timeout" and self._attr_started:
                raise OperationalError(MARKER, MARKER)
            super().__setattr__(name, value)

    connection = BadTimeoutConnection(Cursor([]))
    connection._attr_started = True
    monkeypatch.setattr(mssql_python, "connect", Mock(return_value=connection))
    with pytest.raises(DatabaseOperationError) as caught:
        await MSSQLAdapter(spec()).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert connection.closed


@pytest.mark.asyncio
async def test_worker_returns_no_connection_across_boundary() -> None:
    # After a successful operation the event loop must never see the sync connection object.
    cursor = Cursor([("15.0", "app")])
    adapter = Adapter(spec(), cursors=[cursor])
    info = await adapter.get_server_info()
    assert info.database == "app"
    assert adapter.connections[0].closed
    assert cursor.closed
