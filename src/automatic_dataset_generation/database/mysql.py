"""Bounded, read-only MySQL adapter backed by asyncmy."""

from __future__ import annotations

import math
from contextlib import suppress
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

import asyncmy
from asyncmy.errors import Error as AsyncmyError

if TYPE_CHECKING:
    from asyncmy.connection import Connection
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

_READ_ONLY_SQL = "SET SESSION TRANSACTION READ ONLY"
_MAX_TIMEOUT_MS = 4_294_967_295
_MAX_CONNECT_TIMEOUT = 31_536_000
_MAX_PORT = 65535


def _quote_identifier(value: str) -> str:
    """Quote one MySQL identifier, including embedded backticks."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatabaseAdapterError("identifier must be non-empty text without NUL")
    return "`" + value.replace("`", "``") + "`"


class MySQLAdapter(DatabaseAdapter):
    """One async connection per operation; database grants remain the primary read-only guard."""

    __slots__ = ("_connect_timeout", "_max_sample_rows", "_statement_timeout_ms")

    def __init__(
        self,
        connection_spec: DatabaseConnectionSpec,
        *,
        connect_timeout: float = 5.0,
        statement_timeout: float = 10.0,
        max_sample_rows: int = 100,
    ) -> None:
        if connection_spec.engine is not DatabaseEngine.MYSQL:
            raise DatabaseAdapterError("MySQL adapter requires a MySQL connection")
        if connection_spec.driver not in (None, "asyncmy"):
            raise DatabaseAdapterError("MySQL adapter requires the asyncmy driver")
        self._validate_timeout(connect_timeout, "connect_timeout")
        if connect_timeout > _MAX_CONNECT_TIMEOUT:
            raise DatabaseAdapterError("connect_timeout exceeds the asyncmy maximum")
        self._validate_timeout(statement_timeout, "statement_timeout")
        timeout_ms = max(1, math.ceil(statement_timeout * 1000))
        if timeout_ms > _MAX_TIMEOUT_MS:
            raise DatabaseAdapterError("statement_timeout exceeds the MySQL maximum")
        if (
            isinstance(max_sample_rows, bool)
            or not isinstance(max_sample_rows, int)
            or max_sample_rows <= 0
        ):
            raise DatabaseAdapterError("max_sample_rows must be a positive integer")
        super().__init__(connection_spec)
        self._connection_options()  # Validate URI components without connecting.
        self._connect_timeout = connect_timeout
        self._statement_timeout_ms = timeout_ms
        self._max_sample_rows = max_sample_rows

    async def get_server_info(self) -> DatabaseServerInfo:
        rows, _ = await self._fetch("get_server_info", "SELECT VERSION(), DATABASE()")
        version, database = rows[0]
        return DatabaseServerInfo(
            engine=DatabaseEngine.MYSQL,
            version=str(version),
            database=str(database) if database is not None else None,
        )

    async def list_schemas(self) -> tuple[str, ...]:
        rows, _ = await self._fetch(
            "list_schemas",
            """SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA
            WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql',
                'performance_schema', 'sys') ORDER BY SCHEMA_NAME""",
        )
        return tuple(str(row[0]) for row in rows)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        _quote_identifier(schema)
        rows, _ = await self._fetch(
            "list_tables",
            """SELECT TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %s AND TABLE_TYPE IN ('BASE TABLE', 'VIEW')
            ORDER BY TABLE_NAME""",
            (schema,),
        )
        return tuple(
            TableInfo(
                schema_name=schema,
                table_name=str(name),
                table_type="table" if kind == "BASE TABLE" else "view",
            )
            for name, kind in rows
        )

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        _quote_identifier(schema)
        _quote_identifier(table)
        rows, _ = await self._fetch(
            "describe_table",
            """SELECT c.COLUMN_NAME, c.COLUMN_TYPE, c.IS_NULLABLE,
                EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS AS pk
                    WHERE pk.TABLE_SCHEMA = c.TABLE_SCHEMA
                      AND pk.TABLE_NAME = c.TABLE_NAME
                      AND pk.COLUMN_NAME = c.COLUMN_NAME
                      AND pk.INDEX_NAME = 'PRIMARY')
            FROM INFORMATION_SCHEMA.TABLES AS t
            JOIN INFORMATION_SCHEMA.COLUMNS AS c
              ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
            WHERE t.TABLE_SCHEMA = %s AND t.TABLE_NAME = %s
              AND t.TABLE_TYPE IN ('BASE TABLE', 'VIEW')
            ORDER BY c.ORDINAL_POSITION""",
            (schema, table),
        )
        if not rows:
            raise DatabaseObjectNotFoundError(
                "MySQL operation 'describe_table' found no visible object"
            )
        return TableDescription(
            schema_name=schema,
            table_name=table,
            columns=tuple(
                ColumnInfo(
                    name=str(name),
                    data_type=str(data_type),
                    nullable=nullable == "YES",
                    primary_key=bool(primary_key),
                )
                for name, data_type, nullable, primary_key in rows
            ),
        )

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[RelationshipInfo, ...]:
        _quote_identifier(schema)
        if table is not None:
            _quote_identifier(table)
        query = """SELECT k.TABLE_SCHEMA, k.TABLE_NAME, k.COLUMN_NAME,
                k.REFERENCED_TABLE_SCHEMA, k.REFERENCED_TABLE_NAME,
                k.REFERENCED_COLUMN_NAME, k.CONSTRAINT_NAME
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS k
            WHERE k.REFERENCED_TABLE_SCHEMA IS NOT NULL
              AND k.REFERENCED_TABLE_NAME IS NOT NULL
              AND k.REFERENCED_COLUMN_NAME IS NOT NULL
              AND ((k.TABLE_SCHEMA = %s AND %s IS NULL)
                OR (%s IS NOT NULL AND ((k.TABLE_SCHEMA = %s AND k.TABLE_NAME = %s)
                  OR (k.REFERENCED_TABLE_SCHEMA = %s
                    AND k.REFERENCED_TABLE_NAME = %s))))
            ORDER BY k.TABLE_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME,
                k.ORDINAL_POSITION, k.REFERENCED_TABLE_SCHEMA,
                k.REFERENCED_TABLE_NAME"""
        params = (schema, table, table, schema, table, schema, table)
        rows, _ = await self._fetch("get_relationships", query, params)
        return tuple(
            RelationshipInfo(
                source_schema=str(a),
                source_table=str(b),
                source_column=str(c),
                target_schema=str(d),
                target_table=str(e),
                target_column=str(f),
                constraint_name=str(g),
            )
            for a, b, c, d, e, f, g in rows
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        query = f"SELECT COUNT(*) FROM {_quote_identifier(schema)}.{_quote_identifier(table)}"  # noqa: S608 - quoted identifiers
        rows, _ = await self._fetch("get_row_count", query)
        return int(rows[0][0])

    async def sample_rows(
        self, schema: str, table: str, limit: int = 10, columns: tuple[str, ...] | None = None
    ) -> SampleResult:
        quoted_schema = _quote_identifier(schema)
        quoted_table = _quote_identifier(table)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self._max_sample_rows
        ):
            raise DatabaseAdapterError("sample limit must be between 1 and the configured maximum")
        if columns is not None and not columns:
            raise DatabaseAdapterError("columns must not be empty")
        selected = "*" if columns is None else ", ".join(map(_quote_identifier, columns))
        rows, names = await self._fetch(
            "sample_rows",
            f"SELECT {selected} FROM {quoted_schema}.{quoted_table} LIMIT %s",  # noqa: S608 - quoted identifiers
            (limit + 1,),
        )
        exposed = tuple(rows[:limit])
        return SampleResult(
            schema_name=schema,
            table_name=table,
            columns=names,
            rows=exposed,
            row_count=len(exposed),
            truncated=len(rows) > limit,
        )

    async def _fetch(
        self,
        operation: str,
        query: str,
        params: tuple[object, ...] = (),
    ) -> tuple[list[tuple[Any, ...]], tuple[str, ...]]:
        connection: Connection | None = None
        try:
            connection = await self._connect()
            async with connection.cursor() as cursor:
                await cursor.execute(_READ_ONLY_SQL)
                # SET syntax may not accept a marker. This is an internally validated integer.
                await cursor.execute(
                    f"SET SESSION max_execution_time = {self._statement_timeout_ms}"
                )
                await cursor.execute(query, params)
                rows = [tuple(row) for row in await cursor.fetchall()]
                return rows, tuple(column[0] for column in (cursor.description or ()))
        except AsyncmyError as error:
            if operation == "describe_table" and error.args and error.args[0] in (1044, 1142, 1146):
                raise DatabaseObjectNotFoundError(
                    "MySQL operation 'describe_table' found no visible object"
                ) from None
            raise DatabaseOperationError(f"MySQL operation '{operation}' failed") from None
        finally:
            if connection is not None:
                # Gracefully send QUIT; always release the local transport too.
                try:
                    with suppress(AsyncmyError, OSError):
                        await connection.ensure_closed()
                finally:
                    with suppress(AsyncmyError, OSError):
                        connection.close()

    async def _connect(self) -> Connection:
        """Acquire a private, operation-scoped connection."""
        return await asyncmy.connect(
            **self._connection_options(),
            connect_timeout=self._connect_timeout,
            autocommit=True,
        )

    def _connection_options(self) -> dict[str, object]:
        raw = self._connection_spec.raw_connection_string.get_secret_value()
        try:
            parsed = urlsplit(raw)
            port = 3306 if parsed.port is None else parsed.port
            host = parsed.hostname
            user = parsed.username
            database = unquote(parsed.path[1:]) if parsed.path.startswith("/") else ""
        except ValueError:
            raise DatabaseAdapterError("Invalid MySQL connection components") from None
        if (
            parsed.scheme.casefold() not in ("mysql", "mysql+asyncmy")
            or not host
            or not user
            or not database
            or "\x00" in database
            or parsed.query
            or parsed.fragment
            or not 1 <= port <= _MAX_PORT
        ):
            raise DatabaseAdapterError("Invalid MySQL connection components")
        return {
            "host": host,
            "port": port,
            "user": unquote(user),
            "password": unquote(parsed.password or ""),
            "database": database,
        }

    @staticmethod
    def _validate_timeout(value: float, name: str) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise DatabaseAdapterError(f"{name} must be a positive finite number")
