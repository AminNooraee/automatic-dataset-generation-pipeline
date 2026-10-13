"""Focused temp-file and boundary tests for the production SQLite adapter."""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock
from urllib.parse import quote

import pytest

from automatic_dataset_generation.database import (
    DatabaseAdapterError,
    DatabaseAdapterFactory,
    DatabaseEngine,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
    SQLiteAdapter,
    parse_connection_string,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

MARKER = "sensitive-path-marker"
EXPECTED_RELATIONSHIPS = 2
EXPECTED_ODD_ROWS = 3
EXPECTED_PROGRESS_INTERVAL = 1_000


def spec(uri: str) -> Any:
    return parse_connection_string(uri)


def sqlite_uri(path: Path) -> str:
    return "sqlite:///" + quote(path.resolve().as_posix(), safe="/:")


@pytest.fixture
def database_file() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
        # Question marks are covered at the URI boundary because Windows forbids them in names.
        path = Path(directory) / "metadata # کار.db"
        connection = sqlite3.connect(path)
        connection.executescript(
            """
        PRAGMA foreign_keys = ON;
        CREATE TABLE parent (
            left_id INTEGER,
            right_id INTEGER,
            note TEXT NOT NULL,
            generated TEXT GENERATED ALWAYS AS (note || '!') STORED,
            PRIMARY KEY (left_id, right_id)
        );
        CREATE TABLE child (
            child_id INTEGER PRIMARY KEY,
            parent_left INTEGER,
            parent_right INTEGER,
            payload BLOB,
            FOREIGN KEY (parent_left, parent_right)
                REFERENCES parent (left_id, right_id)
        );
        CREATE TABLE "odd table" ("select" TEXT, "a""b" INTEGER, value REAL);
        CREATE VIEW parent_view AS SELECT left_id, note FROM parent;
        CREATE VIRTUAL TABLE search_index USING fts5(body);
        INSERT INTO parent (left_id, right_id, note) VALUES (1, 2, 'one'), (3, 4, 'two');
        INSERT INTO child VALUES (1, 1, 2, X'00FF'), (2, 3, 4, NULL);
        INSERT INTO "odd table" VALUES ('first', 1, 1.5), ('second', 2, NULL), ('third', 3, 3.5);
            """
        )
        connection.close()
        yield path


class FakeCursor:
    def __init__(
        self,
        *,
        query_only: object = 1,
        failure: Exception | None = None,
        thread_ids: list[int] | None = None,
    ) -> None:
        self.query_only = query_only
        self.failure = failure
        self.thread_ids = thread_ids if thread_ids is not None else []
        self.calls: list[tuple[str, object]] = []
        self.closed = False
        self._sql = ""

    def execute(self, sql: str, parameters: object = None) -> FakeCursor:
        self.thread_ids.append(threading.get_ident())
        self.calls.append((sql, parameters))
        self._sql = sql
        if self.failure is not None and sql == "PRAGMA main.schema_version":
            raise self.failure
        return self

    def fetchone(self) -> tuple[object, ...]:
        self.thread_ids.append(threading.get_ident())
        if self._sql == "PRAGMA query_only":
            return (self.query_only,)
        return (1,)

    def close(self) -> None:
        self.thread_ids.append(threading.get_ident())
        self.closed = True


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.thread_ids = cursor.thread_ids
        self.handlers: list[tuple[object, int]] = []
        self.closed = False

    def cursor(self) -> FakeCursor:
        self.thread_ids.append(threading.get_ident())
        return self._cursor

    def set_progress_handler(self, handler: object, interval: int) -> None:
        self.thread_ids.append(threading.get_ident())
        self.handlers.append((handler, interval))

    def close(self) -> None:
        self.thread_ids.append(threading.get_ident())
        self.closed = True


def test_constructor_accepts_supported_schemes_without_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = Mock()
    monkeypatch.setattr(sqlite3, "connect", connect)
    for uri in (
        "sqlite:///relative/database.db",
        "sqlite+sqlite3:///relative/database.db",
        "SQLITE+SQLITE3:///relative/database.db",
    ):
        adapter = SQLiteAdapter(spec(uri))
        assert "database.db" not in repr(adapter)
    connect.assert_not_called()


def test_wrong_engine_and_driver_are_rejected_before_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = Mock()
    monkeypatch.setattr(sqlite3, "connect", connect)
    for uri in ("mysql://user@host/db", "sqlite+other:///database.db"):
        with pytest.raises(DatabaseAdapterError):
            SQLiteAdapter(spec(uri))
    connect.assert_not_called()


def test_constructor_rejects_unsafe_configuration() -> None:
    for field, value in (
        ("connect_timeout", True),
        ("connect_timeout", 0),
        ("connect_timeout", float("inf")),
        ("connect_timeout", 31_536_001),
        ("statement_timeout", -1),
        ("statement_timeout", float("nan")),
        ("statement_timeout", 31_536_001),
        ("max_sample_rows", True),
        ("max_sample_rows", 0),
    ):
        with pytest.raises(DatabaseAdapterError):
            SQLiteAdapter(spec("sqlite:///database.db"), **{field: value})  # type: ignore[arg-type]


def test_invalid_uri_shapes_are_rejected_safely() -> None:
    for uri in (
        "sqlite://host/database.db",
        "sqlite://user:pass@host/database.db",  # pragma: allowlist secret
        "sqlite://host:123/database.db",
        "sqlite:///database.db?mode=rw",
        "sqlite:///database.db#fragment",
        "sqlite:///:memory:",
        "sqlite://",
        "sqlite:///folder%00/database.db",
        "sqlite://///server/share/database.db",
        "sqlite:///C:drive-relative.db",
    ):
        with pytest.raises(DatabaseAdapterError) as caught:
            SQLiteAdapter(spec(uri))
        assert uri not in str(caught.value)


@pytest.mark.asyncio
async def test_uri_forms_are_encoded_and_connect_timeout_is_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    connect = Mock(return_value=connection)
    monkeypatch.setattr(sqlite3, "connect", connect)
    cases = (
        (
            "sqlite:///relative/a%20b%23%3F%E2%98%83.db",
            "file:relative/a%20b%23%3F%E2%98%83.db?mode=ro",
        ),
        ("sqlite:////absolute/database.db", "file:/absolute/database.db?mode=ro"),
        ("sqlite:///C:/path/database.db", "file:C:/path/database.db?mode=ro"),
    )
    for uri, expected in cases:
        await SQLiteAdapter(spec(uri), connect_timeout=0.25).list_schemas()
        assert connect.call_args.args == (expected,)
        assert connect.call_args.kwargs == {"timeout": 0.25, "uri": True, "autocommit": True}


@pytest.mark.asyncio
async def test_missing_database_is_not_created_and_path_is_redacted(tmp_path: Path) -> None:
    path = tmp_path / MARKER / "missing.db"
    with pytest.raises(DatabaseOperationError) as caught:
        await SQLiteAdapter(spec(sqlite_uri(path))).list_schemas()
    assert MARKER not in str(caught.value)
    assert not path.exists()


@pytest.mark.asyncio
async def test_server_info_and_single_main_schema(database_file: Path) -> None:
    adapter = SQLiteAdapter(spec(sqlite_uri(database_file)))
    info = await adapter.get_server_info()
    assert (info.engine, info.version, info.database) == (
        DatabaseEngine.SQLITE,
        sqlite3.sqlite_version,
        "main",
    )
    assert await adapter.list_schemas() == ("main",)
    assert str(database_file) not in repr(info)


@pytest.mark.asyncio
async def test_table_list_classifies_objects_and_excludes_internal_shadow_tables(
    database_file: Path,
) -> None:
    tables = await SQLiteAdapter(spec(sqlite_uri(database_file))).list_tables("main")
    assert tuple((item.table_name, item.table_type) for item in tables) == (
        ("child", "table"),
        ("odd table", "table"),
        ("parent", "table"),
        ("parent_view", "view"),
        ("search_index", "table"),
    )


@pytest.mark.asyncio
async def test_describe_table_preserves_composite_pk_nullable_and_generated_columns(
    database_file: Path,
) -> None:
    description = await SQLiteAdapter(spec(sqlite_uri(database_file))).describe_table(
        "main", "parent"
    )
    assert tuple(column.name for column in description.columns) == (
        "left_id",
        "right_id",
        "note",
        "generated",
    )
    assert tuple(column.data_type for column in description.columns) == (
        "INTEGER",
        "INTEGER",
        "TEXT",
        "TEXT",
    )
    assert tuple(column.primary_key for column in description.columns) == (True, True, False, False)
    assert tuple(column.nullable for column in description.columns) == (True, True, False, True)


@pytest.mark.asyncio
async def test_describe_view_returns_visible_columns_without_fabricated_pk(
    database_file: Path,
) -> None:
    description = await SQLiteAdapter(spec(sqlite_uri(database_file))).describe_table(
        "main", "parent_view"
    )
    assert tuple(column.name for column in description.columns) == ("left_id", "note")
    assert not any(column.primary_key for column in description.columns)


@pytest.mark.asyncio
async def test_describe_virtual_table_excludes_hidden_implementation_columns(
    database_file: Path,
) -> None:
    description = await SQLiteAdapter(spec(sqlite_uri(database_file))).describe_table(
        "main", "search_index"
    )
    assert tuple(column.name for column in description.columns) == ("body",)


@pytest.mark.asyncio
async def test_missing_or_internal_description_is_safe(database_file: Path) -> None:
    adapter = SQLiteAdapter(spec(sqlite_uri(database_file)))
    for table in (MARKER, "sqlite_schema", "search_index_data"):
        with pytest.raises(DatabaseObjectNotFoundError) as caught:
            await adapter.describe_table("main", table)
        assert table not in str(caught.value)


@pytest.mark.asyncio
async def test_relationships_preserve_composite_pair_order(database_file: Path) -> None:
    relationships = await SQLiteAdapter(spec(sqlite_uri(database_file))).get_relationships("main")
    assert tuple(
        (item.source_table, item.source_column, item.target_table, item.target_column)
        for item in relationships
    ) == (
        ("child", "parent_left", "parent", "left_id"),
        ("child", "parent_right", "parent", "right_id"),
    )
    assert all(item.constraint_name is None for item in relationships)


@pytest.mark.asyncio
async def test_relationship_filter_matches_exact_source_or_target(database_file: Path) -> None:
    adapter = SQLiteAdapter(spec(sqlite_uri(database_file)))
    assert len(await adapter.get_relationships("main", "child")) == EXPECTED_RELATIONSHIPS
    assert len(await adapter.get_relationships("main", "parent")) == EXPECTED_RELATIONSHIPS
    assert await adapter.get_relationships("main", "rent") == ()


@pytest.mark.asyncio
async def test_exact_count_handles_quoted_identifier(database_file: Path) -> None:
    assert (
        await SQLiteAdapter(spec(sqlite_uri(database_file))).get_row_count("main", "odd table")
        == EXPECTED_ODD_ROWS
    )


@pytest.mark.asyncio
async def test_sampling_all_columns_is_bounded_and_preserves_values(database_file: Path) -> None:
    result = await SQLiteAdapter(spec(sqlite_uri(database_file))).sample_rows(
        "main", "child", limit=1
    )
    assert result.columns == ("child_id", "parent_left", "parent_right", "payload")
    assert result.rows == ((1, 1, 2, b"\x00\xff"),)
    assert result.row_count == 1
    assert result.truncated


@pytest.mark.asyncio
async def test_sampling_explicit_columns_preserves_order_and_quoting(database_file: Path) -> None:
    result = await SQLiteAdapter(spec(sqlite_uri(database_file))).sample_rows(
        "main", "odd table", limit=3, columns=('a"b', "select")
    )
    assert result.columns == ('a"b', "select")
    assert result.rows == ((1, "first"), (2, "second"), (3, "third"))
    assert not result.truncated


@pytest.mark.asyncio
async def test_invalid_sampling_input_fails_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    connect = Mock()
    monkeypatch.setattr(sqlite3, "connect", connect)
    adapter = SQLiteAdapter(spec("sqlite:///database.db"), max_sample_rows=2)
    for kwargs in (
        {"limit": True},
        {"limit": 0},
        {"limit": 3},
        {"columns": ()},
        {"columns": ("",)},
    ):
        with pytest.raises(DatabaseAdapterError):
            await adapter.sample_rows("main", "table", **kwargs)
    connect.assert_not_called()


@pytest.mark.asyncio
async def test_non_main_schema_rejected_safely_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = Mock()
    monkeypatch.setattr(sqlite3, "connect", connect)
    adapter = SQLiteAdapter(spec("sqlite:///database.db"))
    with pytest.raises(DatabaseAdapterError) as caught:
        await adapter.list_tables(MARKER)
    assert MARKER not in str(caught.value)
    connect.assert_not_called()


@pytest.mark.asyncio
async def test_read_only_setup_precedes_application_query_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    await SQLiteAdapter(spec("sqlite:///database.db")).list_schemas()
    assert [sql for sql, _params in cursor.calls] == [
        "PRAGMA query_only = ON",
        "PRAGMA query_only",
        "PRAGMA main.schema_version",
    ]
    assert connection.handlers[-1] == (None, 0)
    assert cursor.closed
    assert connection.closed


@pytest.mark.asyncio
async def test_query_only_verification_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = FakeCursor(query_only=0)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    with pytest.raises(DatabaseOperationError):
        await SQLiteAdapter(spec("sqlite:///database.db")).list_schemas()
    assert "PRAGMA main.schema_version" not in [sql for sql, _params in cursor.calls]
    assert cursor.closed
    assert connection.closed


@pytest.mark.asyncio
async def test_sqlite_failure_is_redacted_and_cleanup_errors_do_not_replace_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = FakeCursor(failure=sqlite3.OperationalError(MARKER))
    connection = FakeConnection(cursor)

    def failing_close() -> None:
        connection.closed = True
        raise sqlite3.OperationalError("cleanup")

    connection.close = failing_close  # type: ignore[method-assign]
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    with pytest.raises(DatabaseOperationError) as caught:
        await SQLiteAdapter(spec("sqlite:///database.db")).list_schemas()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__
    assert cursor.closed
    assert connection.closed


@pytest.mark.asyncio
async def test_programming_error_propagates_and_resources_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = FakeCursor(failure=ValueError("programmer failure"))
    connection = FakeConnection(cursor)
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    with pytest.raises(ValueError, match="programmer failure"):
        await SQLiteAdapter(spec("sqlite:///database.db")).list_schemas()
    assert cursor.closed
    assert connection.closed


@pytest.mark.asyncio
async def test_progress_handler_deadline_is_deterministic_and_subsecond(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    monotonic = Mock(side_effect=[10.0, 10.49, 10.5])
    monkeypatch.setattr("automatic_dataset_generation.database.sqlite._monotonic", monotonic)
    await SQLiteAdapter(spec("sqlite:///database.db"), statement_timeout=0.5).list_schemas()
    handler, interval = connection.handlers[0]
    assert callable(handler)
    assert handler() == 0
    assert handler() == 1
    assert interval == EXPECTED_PROGRESS_INTERVAL
    assert connection.handlers[-1] == (None, 0)


@pytest.mark.asyncio
async def test_complete_lifecycle_runs_in_one_worker_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_thread = threading.get_ident()
    thread_ids: list[int] = []
    cursor = FakeCursor(thread_ids=thread_ids)
    connection = FakeConnection(cursor)

    def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        thread_ids.append(threading.get_ident())
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    await SQLiteAdapter(spec("sqlite:///database.db")).list_schemas()
    assert len(set(thread_ids)) == 1
    assert thread_ids[0] != event_thread


@pytest.mark.asyncio
async def test_adapter_operations_leave_disposable_database_unchanged(database_file: Path) -> None:
    before = await asyncio.to_thread(database_file.read_bytes)
    adapter = SQLiteAdapter(spec(sqlite_uri(database_file)))
    await adapter.get_server_info()
    await adapter.list_tables("main")
    await adapter.describe_table("main", "parent")
    await adapter.get_relationships("main")
    await adapter.get_row_count("main", "parent")
    await adapter.sample_rows("main", "parent", 1)
    assert await asyncio.to_thread(database_file.read_bytes) == before


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
    assert forbidden.isdisjoint(dir(SQLiteAdapter))
    factory = DatabaseAdapterFactory({DatabaseEngine.SQLITE: SQLiteAdapter})
    assert isinstance(factory.create(spec("sqlite:///database.db")), SQLiteAdapter)
