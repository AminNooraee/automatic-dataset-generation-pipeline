"""Offline tests for PostgreSQL adapter safety and catalog query semantics."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import psycopg
import pytest
from psycopg import sql

from automatic_dataset_generation.database import (
    DatabaseAdapterError,
    DatabaseConnectionSpec,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
    PostgreSQLAdapter,
    parse_connection_string,
)

EXPECTED_QUERY_CALLS = 3
EXPECTED_COUNT = 7
EXPECTED_RETURNED_ROWS = 2


class Cursor:
    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        names: tuple[str, ...] = (),
        fail_at: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.rows = rows
        self.description = tuple(type("Column", (), {"name": name}) for name in names)
        self.calls: list[tuple[Any, Any]] = []
        self.fail_at = fail_at
        self.failure = failure

    async def __aenter__(self) -> Cursor:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def execute(self, query: Any, params: Any = ()) -> None:
        self.calls.append((query, params))
        if len(self.calls) == self.fail_at and self.failure is not None:
            raise self.failure

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows


class Connection:
    def __init__(self, cursor: Cursor) -> None:
        self._cursor = cursor
        self.closed = False

    def cursor(self) -> Cursor:
        return self._cursor

    async def close(self) -> None:
        self.closed = True


class Adapter(PostgreSQLAdapter):
    def __init__(self, *args: Any, responses: list[Cursor], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.responses = responses
        self.connections: list[Connection] = []

    async def _connect(self) -> Any:
        connection = Connection(self.responses.pop(0))
        self.connections.append(connection)
        return connection


def spec(driver: str | None = None) -> DatabaseConnectionSpec:
    suffix = "+" + driver if driver else ""
    return parse_connection_string(
        f"postgresql{suffix}://user:secret@host/db"  # pragma: allowlist secret
    )


def application_query(cursor: Cursor) -> Any:
    assert len(cursor.calls) == EXPECTED_QUERY_CALLS
    assert cursor.calls[0][0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    assert cursor.calls[1][0] == "SELECT set_config('statement_timeout', %s, false)"
    return cursor.calls[2][0]


@pytest.mark.asyncio
async def test_connection_requests_autocommit_and_normalizes_uppercase_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = AsyncMock(return_value=object())
    monkeypatch.setattr("psycopg.AsyncConnection.connect", connect)
    source_dsn = "POSTGRESQL+PSYCOPG://user:secret@host/db"  # pragma: allowlist secret
    adapter = PostgreSQLAdapter(parse_connection_string(source_dsn))

    await adapter._connect()

    assert connect.await_args_list[-1].kwargs["autocommit"] is True
    expected_dsn = "postgresql://user:secret@host/db"  # pragma: allowlist secret
    assert connect.await_args_list[-1].args[0] == expected_dsn


@pytest.mark.asyncio
async def test_session_setup_precedes_query_and_connection_closes() -> None:
    current = Cursor([("PostgreSQL version", "db")])
    adapter = Adapter(spec(), responses=[current])

    info = await adapter.get_server_info()

    assert info.version == "PostgreSQL version"
    assert info.database == "db"
    assert application_query(current) == "SELECT version(), current_database()"
    assert current.calls[1][1] == ("10000",)
    assert adapter.connections[0].closed


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_at", [1, 2])
async def test_safety_configuration_fails_closed_and_redacts(failure_at: int) -> None:
    current = Cursor([], fail_at=failure_at, failure=psycopg.OperationalError("secret host sql"))
    adapter = Adapter(spec(), responses=[current])

    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()

    assert len(current.calls) == failure_at
    assert "secret" not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert adapter.connections[0].closed


@pytest.mark.asyncio
async def test_driver_failure_redacts_but_programming_error_propagates() -> None:
    driver_cursor = Cursor([], fail_at=3, failure=psycopg.OperationalError("secret host sql"))
    programmer_cursor = Cursor([], fail_at=3, failure=ValueError("programmer failure"))
    adapter = Adapter(spec(), responses=[driver_cursor, programmer_cursor])

    with pytest.raises(DatabaseOperationError) as caught:
        await adapter.list_schemas()
    assert "secret" not in str(caught.value)
    with pytest.raises(ValueError, match="programmer failure"):
        await adapter.list_schemas()
    assert all(connection.closed for connection in adapter.connections)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("seconds", "milliseconds"), [(10.0, "10000"), (0.5, "500"), (0.0004, "1")]
)
async def test_statement_timeout_is_rounded_up(seconds: float, milliseconds: str) -> None:
    current = Cursor([])
    adapter = Adapter(spec(), statement_timeout=seconds, responses=[current])
    await adapter.list_schemas()
    assert current.calls[1][1] == (milliseconds,)


@pytest.mark.asyncio
async def test_schema_filter_is_literal_and_visible() -> None:
    current = Cursor([("pgdata",), ("public",)])
    adapter = Adapter(spec(), responses=[current])

    assert await adapter.list_schemas() == ("pgdata", "public")
    query = application_query(current)
    assert "left(nspname, 3) <> 'pg_'" in query
    assert "information_schema" in query
    assert "has_schema_privilege" in query
    assert "ORDER BY nspname" in query


@pytest.mark.asyncio
async def test_list_tables_restricts_types() -> None:
    current = Cursor([("events", "BASE TABLE"), ("report", "VIEW")])
    adapter = Adapter(spec(), responses=[current])
    tables = await adapter.list_tables("public")
    assert tuple(table.table_type for table in tables) == ("table", "view")
    assert "table_type IN ('BASE TABLE', 'VIEW')" in application_query(current)
    assert current.calls[2][1] == ("public",)


@pytest.mark.asyncio
async def test_describe_boolean_nullable_composite_pk_and_single_query() -> None:
    current = Cursor(
        [
            ("first", "integer", False, True),
            ("second", "integer", False, True),
            ("optional", "text", True, False),
        ]
    )
    adapter = Adapter(spec(), responses=[current])

    description = await adapter.describe_table("public", "composite")

    assert tuple(column.name for column in description.columns) == ("first", "second", "optional")
    assert tuple(column.nullable for column in description.columns) == (False, False, True)
    assert tuple(column.primary_key for column in description.columns) == (True, True, False)
    assert len(adapter.connections) == 1
    query = application_query(current)
    assert "pg_constraint AS pk" in query
    assert "pk.conrelid = relation.oid" in query
    assert "attribute.attnum = ANY (pk.conkey)" in query
    assert "attribute.attnum > 0 AND NOT attribute.attisdropped" in query
    assert "ORDER BY attribute.attnum" in query
    assert "information_schema" not in query


@pytest.mark.asyncio
async def test_missing_or_invisible_object_has_secret_safe_error() -> None:
    current = Cursor([])
    adapter = Adapter(spec(), responses=[current])
    with pytest.raises(DatabaseObjectNotFoundError) as caught:
        await adapter.describe_table("public", "secret_table")
    assert "secret_table" not in str(caught.value)
    query = application_query(current)
    assert "has_table_privilege(relation.oid, 'SELECT')" in query
    assert "has_schema_privilege(namespace.oid, 'USAGE')" in query


@pytest.mark.asyncio
async def test_relationships_pair_fk_columns_and_scope_exact_table() -> None:
    rows = [
        ("billing", "invoices", "a", "public", "orders", "y", "fk"),
        ("billing", "invoices", "b", "public", "orders", "x", "fk"),
    ]
    current = Cursor(rows)
    adapter = Adapter(spec(), responses=[current])

    relationships = await adapter.get_relationships("public", "orders")

    assert tuple((r.source_column, r.target_column) for r in relationships) == (
        ("a", "y"),
        ("b", "x"),
    )
    query = application_query(current)
    assert "unnest(con.conkey, con.confkey) WITH ORDINALITY" in query
    assert "source_class.relname = %s" in query
    assert "target_class.relname = %s" in query
    assert "has_table_privilege(con.conrelid, 'SELECT')" in query
    assert "has_table_privilege(con.confrelid, 'SELECT')" in query
    assert "::text IS NULL" in query
    assert current.calls[2][1] == (
        "public",
        "orders",
        "orders",
        "public",
        "orders",
        "public",
        "orders",
    )


@pytest.mark.asyncio
async def test_exact_count_uses_quoted_identifiers() -> None:
    current = Cursor([(7,)])
    adapter = Adapter(spec(), responses=[current])
    count = await adapter.get_row_count("weird schema", 'events"; DROP TABLE users; --')
    assert count == EXPECTED_COUNT
    query = application_query(current)
    assert isinstance(query, sql.Composed)
    assert (
        query.as_string() == 'SELECT count(*) FROM "weird schema"."events""; DROP TABLE users; --"'
    )


@pytest.mark.asyncio
async def test_sampling_is_bounded_quoted_and_uses_cursor_metadata() -> None:
    current = Cursor([(1,), (2,), (3,)], ("select",))
    adapter = Adapter(spec(), max_sample_rows=2, responses=[current])
    result = await adapter.sample_rows("weird schema", "events", 2, ("select",))
    assert result.rows == ((1,), (2,))
    assert result.row_count == EXPECTED_RETURNED_ROWS
    assert result.truncated is True
    assert result.columns == ("select",)
    assert current.calls[2][1] == (3,)
    assert (
        application_query(current).as_string()
        == 'SELECT "select" FROM "weird schema"."events" LIMIT %s'
    )


@pytest.mark.asyncio
async def test_sampling_without_extra_row_is_not_truncated() -> None:
    current = Cursor([(1,)], ("id",))
    result = await Adapter(spec(), responses=[current]).sample_rows("public", "events", 2)
    assert result.rows == ((1,),)
    assert result.truncated is False
    assert application_query(current).as_string() == 'SELECT * FROM "public"."events" LIMIT %s'


@pytest.mark.parametrize("value", [True, 0, float("inf")])
def test_constructor_rejects_unsafe_configuration(value: object) -> None:
    with pytest.raises(DatabaseAdapterError):
        PostgreSQLAdapter(spec(), connect_timeout=value)  # type: ignore[arg-type]


def test_constructor_rejects_engine_and_driver_without_connecting() -> None:
    with pytest.raises(DatabaseAdapterError):
        PostgreSQLAdapter(parse_connection_string("mysql://host/db"))
    with pytest.raises(DatabaseAdapterError):
        PostgreSQLAdapter(spec("asyncpg"))
    assert "secret" not in repr(PostgreSQLAdapter(spec("psycopg")))


@pytest.mark.asyncio
async def test_relationships_without_table_limit_source_schema() -> None:
    current = Cursor([])
    adapter = Adapter(spec(), responses=[current])

    assert await adapter.get_relationships("billing") == ()
    query = application_query(current)
    assert "source_namespace.nspname = %s AND %s::text IS NULL" in query
    assert current.calls[2][1] == ("billing", None, None, "billing", None, "billing", None)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, 101, True, 1.5])
async def test_sampling_rejects_invalid_limits_before_connect(limit: object) -> None:
    adapter = Adapter(spec(), responses=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("public", "events", limit=limit)  # type: ignore[arg-type]
    assert adapter.connections == []


@pytest.mark.asyncio
async def test_sampling_rejects_empty_columns_before_connect() -> None:
    adapter = Adapter(spec(), responses=[])
    with pytest.raises(DatabaseAdapterError):
        await adapter.sample_rows("public", "events", columns=())
    assert adapter.connections == []


def test_generic_sql_methods_are_not_public() -> None:
    forbidden = {
        "execute",
        "execute_sql",
        "query",
        "raw_query",
        "run_sql",
        "run_any_sql",
        "custom_sql",
    }
    assert forbidden.isdisjoint(dir(PostgreSQLAdapter))
