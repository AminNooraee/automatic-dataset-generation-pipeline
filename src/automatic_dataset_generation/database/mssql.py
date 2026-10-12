"""Bounded, read-only Microsoft SQL Server adapter backed by mssql-python."""

from __future__ import annotations

import asyncio
import math
from contextlib import suppress
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

import mssql_python
from mssql_python import Error as MssqlError

if TYPE_CHECKING:
    from mssql_python.connection import Connection as MssqlConnection

from automatic_dataset_generation.database.adapter import DatabaseAdapter
from automatic_dataset_generation.database.connection import (
    DatabaseConnectionSpec,
    DatabaseEngine,
)
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

# Adapter policy cap for both the login and per-statement timeouts, expressed in seconds. This is
# an adapter-level policy bound, not a claim about SQL Server's own maximum.
_MAX_TIMEOUT_SECONDS = 31_536_000
_DEFAULT_PORT = 1433
_MAX_PORT = 65535

_NCHAR_TYPES = frozenset({"nchar", "nvarchar"})
_LENGTH_TYPES = frozenset({"char", "varchar", "nchar", "nvarchar", "binary", "varbinary"})
_DECIMAL_TYPES = frozenset({"decimal", "numeric"})
_SCALE_TYPES = frozenset({"datetime2", "time", "datetimeoffset"})


def _quote_identifier(value: str) -> str:
    """Quote one SQL Server identifier using bracket delimiters, doubling any embedded ]."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatabaseAdapterError("identifier must be non-empty text without NUL")
    return "[" + value.replace("]", "]]") + "]"


def _format_sql_server_type(
    type_name: object, max_length: object, precision: object, scale: object
) -> str:
    """Render a deterministic declared type string from sys.types/sys.columns values.

    The describing query joins ``sys.types`` on ``user_type_id``, so each column maps to exactly one
    ``sys.types`` row — its actual declared type, including aliases and user-defined types — with no
    duplicated rows. Standard system types render length/precision/scale. Character and binary
    lengths use ``max_length`` (``nchar``/``nvarchar`` and the byte-based ``binary`` family), and
    ``max_length == -1`` renders ``max``. Any other type name — alias or user-defined type — is
    returned verbatim, so no incorrect rendering is ever fabricated.
    """
    name = str(type_name)
    if name in _DECIMAL_TYPES:
        return f"{name}({precision},{scale})"
    if name in _SCALE_TYPES:
        return f"{name}({scale})"
    if name in _LENGTH_TYPES:
        if max_length == -1:
            return f"{name}(max)"
        length = max_length // 2 if name in _NCHAR_TYPES else max_length  # type: ignore[operator]
        return f"{name}({length})"
    return name


def _server_endpoint(host: str, port: int) -> str:
    """Compose the ODBC Server endpoint. IPv6 literals are bracketed per ODBC convention."""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host},{port}"


class MSSQLAdapter(DatabaseAdapter):
    """One mssql-python connection per operation, bridged over asyncio with least-privilege reads.

    SQL Server has no PostgreSQL/MySQL-style session read-only switch, so read-only is enforced by
    a least-privilege principal plus allowlisted, SELECT-only statements. ``ApplicationIntent``
    read-only is a workload routing hint, not an authorization boundary.
    """

    __slots__ = ("_login_timeout", "_max_sample_rows", "_statement_timeout")

    def __init__(
        self,
        connection_spec: DatabaseConnectionSpec,
        *,
        connect_timeout: float = 5.0,
        statement_timeout: float = 10.0,
        max_sample_rows: int = 100,
    ) -> None:
        if connection_spec.engine is not DatabaseEngine.MSSQL:
            raise DatabaseAdapterError("SQL Server adapter requires an MSSQL connection")
        if connection_spec.driver not in (None, "mssql-python"):
            raise DatabaseAdapterError("SQL Server adapter requires the mssql-python driver")
        self._validate_timeout(connect_timeout, "connect_timeout")
        if connect_timeout > _MAX_TIMEOUT_SECONDS:
            raise DatabaseAdapterError("connect_timeout exceeds the maximum")
        self._validate_timeout(statement_timeout, "statement_timeout")
        if statement_timeout > _MAX_TIMEOUT_SECONDS:
            raise DatabaseAdapterError("statement_timeout exceeds the maximum")
        if (
            isinstance(max_sample_rows, bool)
            or not isinstance(max_sample_rows, int)
            or max_sample_rows <= 0
        ):
            raise DatabaseAdapterError("max_sample_rows must be a positive integer")
        super().__init__(connection_spec)
        self._connection_options()  # Validate URI components without connecting.
        # ODBC login and query timeouts operate at whole-second resolution; CEIL so a positive
        # sub-second value never truncates to zero.
        self._login_timeout = math.ceil(connect_timeout)
        self._statement_timeout = math.ceil(statement_timeout)
        self._max_sample_rows = max_sample_rows

    async def get_server_info(self) -> DatabaseServerInfo:
        rows, _ = await self._fetch(
            "get_server_info",
            "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), DB_NAME()",
        )
        version, database = rows[0]
        return DatabaseServerInfo(
            engine=DatabaseEngine.MSSQL,
            version=str(version) if version is not None else None,
            database=str(database) if database is not None else None,
        )

    async def list_schemas(self) -> tuple[str, ...]:
        rows, _ = await self._fetch(
            "list_schemas",
            """SELECT s.name
            FROM sys.schemas AS s
            JOIN sys.objects AS o ON o.schema_id = s.schema_id
            WHERE o.type IN ('U', 'V')
              AND s.name NOT IN ('sys', 'INFORMATION_SCHEMA')
              AND HAS_PERMS_BY_NAME(
                  QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', 'SELECT') = 1
            GROUP BY s.name
            ORDER BY s.name""",
        )
        return tuple(str(row[0]) for row in rows)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        _quote_identifier(schema)
        rows, _ = await self._fetch(
            "list_tables",
            """SELECT o.name, o.type
            FROM sys.objects AS o
            JOIN sys.schemas AS s ON s.schema_id = o.schema_id
            WHERE s.name = ?
              AND o.type IN ('U', 'V')
              AND o.is_ms_shipped = 0
              AND HAS_PERMS_BY_NAME(
                  QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', 'SELECT') = 1
            ORDER BY o.name""",
            (schema,),
        )
        return tuple(
            TableInfo(
                schema_name=schema,
                table_name=str(name),
                table_type="view" if kind == "V" else "table",
            )
            for name, kind in rows
        )

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        _quote_identifier(schema)
        _quote_identifier(table)
        rows, _ = await self._fetch(
            "describe_table",
            """SELECT c.name, t.name, c.is_nullable, c.max_length, c.precision, c.scale,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM sys.indexes AS i
                        JOIN sys.index_columns AS ic
                          ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                        WHERE i.object_id = o.object_id AND i.is_primary_key = 1
                          AND ic.column_id = c.column_id
                    ) THEN CAST(1 AS bit)
                    ELSE CAST(0 AS bit)
                END
            FROM sys.schemas AS s
            JOIN sys.objects AS o ON o.schema_id = s.schema_id
            JOIN sys.columns AS c ON c.object_id = o.object_id
            JOIN sys.types AS t ON t.user_type_id = c.user_type_id
            WHERE s.name = ? AND o.name = ?
              AND o.type IN ('U', 'V')
              AND c.is_hidden = 0
              AND HAS_PERMS_BY_NAME(
                  QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', 'SELECT') = 1
            ORDER BY c.column_id""",
            (schema, table),
        )
        if not rows:
            raise DatabaseObjectNotFoundError(
                "SQL Server operation 'describe_table' found no visible object"
            )
        return TableDescription(
            schema_name=schema,
            table_name=table,
            columns=tuple(
                ColumnInfo(
                    name=str(name),
                    data_type=_format_sql_server_type(type_name, max_length, precision, scale),
                    nullable=bool(is_nullable),
                    primary_key=bool(is_pk),
                )
                for name, type_name, is_nullable, max_length, precision, scale, is_pk in rows
            ),
        )

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[RelationshipInfo, ...]:
        _quote_identifier(schema)
        if table is not None:
            _quote_identifier(table)
        query = """SELECT ss.name, st.name, sc.name,
                rs.name, rt.name, rc.name, fk.name
            FROM sys.foreign_keys AS fk
            JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
            JOIN sys.objects AS st ON st.object_id = fkc.parent_object_id
            JOIN sys.schemas AS ss ON ss.schema_id = st.schema_id
            JOIN sys.columns AS sc
              ON sc.object_id = fkc.parent_object_id AND sc.column_id = fkc.parent_column_id
            JOIN sys.objects AS rt ON rt.object_id = fkc.referenced_object_id
            JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id
            JOIN sys.columns AS rc
              ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
            WHERE ((ss.name = ? AND ? IS NULL)
              OR (? IS NOT NULL AND ((ss.name = ? AND st.name = ?)
                OR (rs.name = ? AND rt.name = ?))))
              AND HAS_PERMS_BY_NAME(
                  QUOTENAME(ss.name) + N'.' + QUOTENAME(st.name), 'OBJECT', 'SELECT') = 1
              AND HAS_PERMS_BY_NAME(
                  QUOTENAME(rs.name) + N'.' + QUOTENAME(rt.name), 'OBJECT', 'SELECT') = 1
            ORDER BY ss.name, st.name, fk.name, fkc.constraint_column_id, rs.name, rt.name"""
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
                constraint_name=str(g) if g is not None else None,
            )
            for a, b, c, d, e, f, g in rows
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        query = f"SELECT COUNT_BIG(*) FROM {_quote_identifier(schema)}.{_quote_identifier(table)}"  # noqa: S608 - quoted identifiers
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
        # SQL Server uses TOP; the row count is an internally produced int (limit + 1), never text.
        query = f"SELECT TOP {limit + 1} {selected} FROM {quoted_schema}.{quoted_table}"  # noqa: S608 - quoted identifiers
        rows, names = await self._fetch("sample_rows", query)
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
        try:
            return await asyncio.to_thread(self._run_query_sync, query, params)
        except MssqlError:
            raise DatabaseOperationError(f"SQL Server operation '{operation}' failed") from None

    def _run_query_sync(
        self, query: str, params: tuple[object, ...]
    ) -> tuple[list[tuple[Any, ...]], tuple[str, ...]]:
        """Run the whole synchronous connection lifecycle inside one worker thread.

        The connection is created, its per-statement timeout set, the single query executed and
        fetched, and both cursor and connection are released, all here. Nothing is returned to the
        event loop except plain rows and metadata.
        """
        connection: MssqlConnection | None = None
        try:
            connection = self._connect()
            # The query timeout must be set before cursor creation; cursors snapshot it.
            connection.timeout = self._statement_timeout
            cursor = connection.cursor()
            try:
                cursor.execute(query, params)
                rows = [tuple(row) for row in cursor.fetchall()]
                names = tuple(column[0] for column in (cursor.description or ()))
                return rows, names
            finally:
                with suppress(MssqlError, OSError):
                    cursor.close()
        finally:
            if connection is not None:
                with suppress(MssqlError, OSError):
                    connection.close()

    def _connect(self) -> MssqlConnection:
        """Acquire a private, operation-scoped connection.

        Dynamic values and the trusted security configuration are passed as keyword arguments so
        mssql-python escapes them; credentials are never interpolated into a raw string by us.
        """
        return mssql_python.connect(
            "", autocommit=True, timeout=self._login_timeout, **self._connection_options()
        )

    def _connection_options(self) -> dict[str, Any]:
        raw = self._connection_spec.raw_connection_string.get_secret_value()
        try:
            parsed = urlsplit(raw)
            port = _DEFAULT_PORT if parsed.port is None else parsed.port
            host = parsed.hostname
            user = parsed.username
            database = unquote(parsed.path[1:]) if parsed.path.startswith("/") else ""
        except ValueError:
            raise DatabaseAdapterError("Invalid SQL Server connection components") from None
        if (
            parsed.scheme.casefold()
            not in ("mssql", "sqlserver", "mssql+mssql-python", "sqlserver+mssql-python")
            or not host
            or not user
            or not database
            or self._has_endpoint_control_chars(host)
            or "\x00" in database
            or parsed.query
            or parsed.fragment
            or not 1 <= port <= _MAX_PORT
        ):
            raise DatabaseAdapterError("Invalid SQL Server connection components")
        # Encrypt=yes / TrustServerCertificate=no are a trusted static security configuration; the
        # ApplicationIntent is a workload routing hint, not an authorization boundary.
        return {
            "server": _server_endpoint(host, port),
            "uid": unquote(user),
            "pwd": unquote(parsed.password or ""),
            "database": database,
            "encrypt": "yes",
            "trustservercertificate": "no",
            "applicationintent": "readonly",
        }

    @staticmethod
    def _has_endpoint_control_chars(host: str) -> bool:
        """Reject host values that could alter the ODBC Server target syntax."""
        if not host:
            return True
        if any(ch in host for ch in (";", ",", "\\", "\x00")):
            return True
        if any(ch.isspace() for ch in host):
            return True
        return host != host.strip()

    @staticmethod
    def _validate_timeout(value: float, name: str) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise DatabaseAdapterError(f"{name} must be a positive finite number")
