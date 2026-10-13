"""Bounded, read-only SQLite adapter backed by Python's standard library."""

from __future__ import annotations

import asyncio
import math
import sqlite3
import time
from contextlib import suppress
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import quote, unquote, urlsplit

from automatic_dataset_generation.database.adapter import DatabaseAdapter
from automatic_dataset_generation.database.connection import DatabaseConnectionSpec, DatabaseEngine
from automatic_dataset_generation.database.errors import (
    DatabaseAdapterError,
    DatabaseObjectNotFoundError,
    DatabaseOperationError,
)
from automatic_dataset_generation.database.models import (
    ColumnInfo,
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_MAX_TIMEOUT_SECONDS = 31_536_000
_PROGRESS_INSTRUCTION_INTERVAL = 1_000
_DRIVE_PREFIX_LENGTH = 2
_monotonic = time.monotonic
_T = TypeVar("_T")


def _quote_identifier(value: str) -> str:
    """Quote one SQLite identifier with SQL-standard double quotes."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatabaseAdapterError("identifier must be non-empty text without NUL")
    return '"' + value.replace('"', '""') + '"'


def _validate_schema(schema: str) -> None:
    """Require the sole logical schema exposed by this adapter."""
    if not isinstance(schema, str) or schema != "main":
        raise DatabaseAdapterError("SQLite adapter supports only the main schema")


class SQLiteAdapter(DatabaseAdapter):
    """One local, read-only sqlite3 connection per operation on one worker thread."""

    __slots__ = ("_connect_timeout", "_file_uri", "_max_sample_rows", "_statement_timeout")

    def __init__(
        self,
        connection_spec: DatabaseConnectionSpec,
        *,
        connect_timeout: float = 5.0,
        statement_timeout: float = 10.0,
        max_sample_rows: int = 100,
    ) -> None:
        if connection_spec.engine is not DatabaseEngine.SQLITE:
            raise DatabaseAdapterError("SQLite adapter requires a SQLite connection")
        if connection_spec.driver not in (None, "sqlite3"):
            raise DatabaseAdapterError("SQLite adapter requires the sqlite3 driver")
        self._validate_timeout(connect_timeout, "connect_timeout")
        self._validate_timeout(statement_timeout, "statement_timeout")
        if connect_timeout > _MAX_TIMEOUT_SECONDS:
            raise DatabaseAdapterError("connect_timeout exceeds the maximum")
        if statement_timeout > _MAX_TIMEOUT_SECONDS:
            raise DatabaseAdapterError("statement_timeout exceeds the maximum")
        if (
            isinstance(max_sample_rows, bool)
            or not isinstance(max_sample_rows, int)
            or max_sample_rows <= 0
        ):
            raise DatabaseAdapterError("max_sample_rows must be a positive integer")
        super().__init__(connection_spec)
        self._file_uri = self._build_read_only_file_uri()
        self._connect_timeout = float(connect_timeout)
        self._statement_timeout = float(statement_timeout)
        self._max_sample_rows = max_sample_rows

    async def get_server_info(self) -> DatabaseServerInfo:
        version = await asyncio.to_thread(self._sync_server_info)
        return DatabaseServerInfo(engine=DatabaseEngine.SQLITE, version=version, database="main")

    async def list_schemas(self) -> tuple[str, ...]:
        await asyncio.to_thread(self._sync_validate_database)
        return ("main",)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        _validate_schema(schema)
        rows = await asyncio.to_thread(self._sync_table_list)
        return tuple(
            TableInfo(
                schema_name="main",
                table_name=name,
                table_type="view" if kind == "view" else "table",
            )
            for name, kind in rows
        )

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        _validate_schema(schema)
        quoted_table = _quote_identifier(table)
        rows = await asyncio.to_thread(self._sync_describe_table, table, quoted_table)
        if rows is None:
            raise DatabaseObjectNotFoundError(
                "SQLite operation 'describe_table' found no visible object"
            )
        return TableDescription(
            schema_name="main",
            table_name=table,
            columns=tuple(
                ColumnInfo(
                    name=name,
                    data_type=declared_type,
                    nullable=not bool(not_null),
                    primary_key=bool(primary_key_position),
                )
                for (
                    _cid,
                    name,
                    declared_type,
                    not_null,
                    _default,
                    primary_key_position,
                    hidden,
                ) in rows
                if hidden != 1
            ),
        )

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[RelationshipInfo, ...]:
        _validate_schema(schema)
        if table is not None:
            _quote_identifier(table)
        rows = await asyncio.to_thread(self._sync_relationships)
        return tuple(
            RelationshipInfo(
                source_schema="main",
                source_table=source_table,
                source_column=source_column,
                target_schema="main",
                target_table=target_table,
                target_column=target_column,
                constraint_name=None,
            )
            for source_table, _fk_id, _sequence, target_table, source_column, target_column in rows
            if table is None or table in (source_table, target_table)
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        _validate_schema(schema)
        quoted_table = _quote_identifier(table)
        return await asyncio.to_thread(self._sync_row_count, quoted_table)

    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: tuple[str, ...] | None = None,
    ) -> SampleResult:
        _validate_schema(schema)
        quoted_table = _quote_identifier(table)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self._max_sample_rows
        ):
            raise DatabaseAdapterError("limit must be an integer within the configured maximum")
        if columns is not None and not columns:
            raise DatabaseAdapterError("columns must be a non-empty tuple when provided")
        selected = (
            ", ".join(_quote_identifier(column) for column in columns)
            if columns is not None
            else "*"
        )
        rows, result_columns = await asyncio.to_thread(
            self._sync_sample_rows, quoted_table, selected, limit + 1
        )
        exposed = rows[:limit]
        return SampleResult(
            schema_name="main",
            table_name=table,
            columns=result_columns,
            rows=exposed,
            row_count=len(exposed),
            truncated=len(rows) > limit,
        )

    def _sync_server_info(self) -> str:
        def operation(cursor: sqlite3.Cursor) -> str:
            row = cursor.execute("SELECT sqlite_version()").fetchone()
            if row is None:
                raise DatabaseOperationError("SQLite operation 'get_server_info' returned no data")
            return str(row[0])

        return self._run("get_server_info", operation)

    def _sync_validate_database(self) -> None:
        def operation(cursor: sqlite3.Cursor) -> None:
            cursor.execute("PRAGMA main.schema_version").fetchone()

        self._run("list_schemas", operation)

    def _sync_table_list(self) -> list[tuple[str, str]]:
        def operation(cursor: sqlite3.Cursor) -> list[tuple[str, str]]:
            return self._eligible_objects(cursor)

        return self._run("list_tables", operation)

    def _sync_describe_table(
        self, table: str, quoted_table: str
    ) -> list[tuple[int, str, str, int, object, int, int]] | None:
        def operation(
            cursor: sqlite3.Cursor,
        ) -> list[tuple[int, str, str, int, object, int, int]] | None:
            if table not in {name for name, _kind in self._eligible_objects(cursor)}:
                return None
            rows = cursor.execute(f"PRAGMA main.table_xinfo({quoted_table})").fetchall()
            return [
                (
                    int(cid),
                    str(name),
                    str(declared_type),
                    int(not_null),
                    default,
                    int(primary_key_position),
                    int(hidden),
                )
                for (
                    cid,
                    name,
                    declared_type,
                    not_null,
                    default,
                    primary_key_position,
                    hidden,
                ) in rows
            ]

        return self._run("describe_table", operation)

    def _sync_relationships(self) -> list[tuple[str, int, int, str, str, str]]:
        def operation(cursor: sqlite3.Cursor) -> list[tuple[str, int, int, str, str, str]]:
            relationships: list[tuple[str, int, int, str, str, str]] = []
            for source_table, kind in self._eligible_objects(cursor):
                if kind == "view":
                    continue
                quoted_source = _quote_identifier(source_table)
                foreign_keys = cursor.execute(
                    f"PRAGMA main.foreign_key_list({quoted_source})"
                ).fetchall()
                for (
                    fk_id,
                    sequence,
                    target_table,
                    source_column,
                    target_column,
                    *_rest,
                ) in foreign_keys:
                    relationships.append(
                        (
                            source_table,
                            int(fk_id),
                            int(sequence),
                            str(target_table),
                            str(source_column),
                            str(target_column),
                        )
                    )
            return sorted(relationships, key=lambda row: (row[0], row[1], row[2]))

        return self._run("get_relationships", operation)

    def _sync_row_count(self, quoted_table: str) -> int:
        def operation(cursor: sqlite3.Cursor) -> int:
            row = cursor.execute(
                f'SELECT COUNT(*) FROM "main".{quoted_table}'  # noqa: S608
            ).fetchone()
            if row is None:
                raise DatabaseOperationError("SQLite operation 'get_row_count' returned no data")
            return int(row[0])

        return self._run("get_row_count", operation)

    def _sync_sample_rows(
        self, quoted_table: str, selected: str, fetch_limit: int
    ) -> tuple[tuple[tuple[object, ...], ...], tuple[str, ...]]:
        def operation(
            cursor: sqlite3.Cursor,
        ) -> tuple[tuple[tuple[object, ...], ...], tuple[str, ...]]:
            cursor.execute(
                f'SELECT {selected} FROM "main".{quoted_table} LIMIT ?',  # noqa: S608
                (fetch_limit,),
            )
            rows = tuple(tuple(row) for row in cursor.fetchmany(fetch_limit))
            description = cursor.description or ()
            return rows, tuple(str(column[0]) for column in description)

        return self._run("sample_rows", operation)

    def _run(self, operation_name: str, operation: Callable[[sqlite3.Cursor], _T]) -> _T:
        connection: sqlite3.Connection | None = None
        cursor: sqlite3.Cursor | None = None
        try:
            connection = sqlite3.connect(
                self._file_uri,
                timeout=self._connect_timeout,
                uri=True,
                autocommit=True,
            )
            cursor = connection.cursor()
            cursor.execute("PRAGMA query_only = ON")
            enabled = cursor.execute("PRAGMA query_only").fetchone()
            if enabled is None or enabled[0] != 1:
                raise DatabaseOperationError(
                    f"SQLite operation '{operation_name}' could not enable read-only mode"
                )
            deadline = _monotonic() + self._statement_timeout

            def progress() -> int:
                return int(_monotonic() >= deadline)

            connection.set_progress_handler(progress, _PROGRESS_INSTRUCTION_INTERVAL)
            return operation(cursor)
        except sqlite3.Error:
            raise DatabaseOperationError(f"SQLite operation '{operation_name}' failed") from None
        finally:
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.set_progress_handler(None, 0)
            if cursor is not None:
                with suppress(sqlite3.Error):
                    cursor.close()
            if connection is not None:
                with suppress(sqlite3.Error):
                    connection.close()

    @staticmethod
    def _eligible_objects(cursor: sqlite3.Cursor) -> list[tuple[str, str]]:
        return sorted(
            (str(name), str(kind))
            for row_schema, name, kind, _ncol, _without_rowid, _strict in cursor.execute(
                "PRAGMA main.table_list"
            ).fetchall()
            if row_schema == "main"
            and kind in ("table", "virtual", "view")
            and not str(name).casefold().startswith("sqlite_")
        )

    def _build_read_only_file_uri(self) -> str:
        raw = self._connection_spec.raw_connection_string.get_secret_value()
        try:
            parsed = urlsplit(raw)
            decoded_path = unquote(parsed.path, errors="strict")
            port = parsed.port
        except (UnicodeError, ValueError):
            raise DatabaseAdapterError("Invalid SQLite connection components") from None
        if (
            parsed.scheme.casefold() not in ("sqlite", "sqlite+sqlite3")
            or parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname is not None
            or port is not None
            or parsed.query
            or parsed.fragment
            or not decoded_path.startswith("/")
        ):
            raise DatabaseAdapterError("Invalid SQLite connection components")
        local_path = decoded_path[1:]
        if (
            not local_path
            or local_path == ":memory:"
            or "\x00" in local_path
            or local_path.startswith(("//", "\\"))
            or (
                len(local_path) >= _DRIVE_PREFIX_LENGTH
                and local_path[1] == ":"
                and (
                    not local_path[0].isalpha()
                    or len(local_path) == _DRIVE_PREFIX_LENGTH
                    or local_path[_DRIVE_PREFIX_LENGTH] != "/"
                )
            )
        ):
            raise DatabaseAdapterError("Invalid SQLite connection components")
        return "file:" + quote(local_path, safe="/:") + "?mode=ro"

    @staticmethod
    def _validate_timeout(value: float, name: str) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise DatabaseAdapterError(f"{name} must be a positive finite number")
