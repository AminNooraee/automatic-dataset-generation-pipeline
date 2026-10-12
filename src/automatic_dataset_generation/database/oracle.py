"""Bounded, read-only Oracle adapter backed by python-oracledb Thin mode."""

from __future__ import annotations

import math
from contextlib import suppress
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import unquote, urlsplit

import oracledb

if TYPE_CHECKING:
    from collections.abc import Mapping

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

_READ_ONLY_SQL = "SET TRANSACTION READ ONLY"
_DEFAULT_PORT = 1521
_MAX_PORT = 65535
_MAX_CONNECT_TIMEOUT_SECONDS = 31_536_000
# python-oracledb 26.0.1 Thin stores call_timeout in a uint32_t, in milliseconds.
_MAX_CALL_TIMEOUT_MS = 4_294_967_295
_NOT_FOUND_OR_INACCESSIBLE_CODES = frozenset({942, 1031})


def _quote_identifier(value: str) -> str:
    """Quote one Oracle identifier, preserving case and doubling embedded quotes."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatabaseAdapterError("identifier must be non-empty text without NUL")
    return '"' + value.replace('"', '""') + '"'


def _format_oracle_type(
    data_type: object,
    details: tuple[object, object, object, object, object],
) -> str:
    """Render common declared Oracle types without inventing unsupported details."""
    data_length, precision, scale, char_length, char_used = details
    name = str(data_type)
    if name == "NUMBER" and precision is not None:
        return f"{name}({precision})" if scale is None else f"{name}({precision},{scale})"
    if name == "FLOAT" and precision is not None:
        return f"{name}({precision})"
    if name in {"CHAR", "VARCHAR2", "NCHAR", "NVARCHAR2"}:
        length = char_length if char_used == "C" else data_length
        if length is not None:
            semantics = " CHAR" if char_used == "C" else " BYTE"
            return f"{name}({length}{semantics})"
    if name == "RAW" and data_length is not None:
        return f"{name}({data_length})"
    return name


def _error_code(error: oracledb.DatabaseError) -> int | None:
    """Extract only the numeric Oracle code needed for safe domain classification."""
    if not error.args:
        return None
    code = getattr(error.args[0], "code", None)
    return code if isinstance(code, int) and not isinstance(code, bool) else None


class OracleAdapter(DatabaseAdapter):
    """One native async Thin connection and read-only transaction per operation.

    The production principal must still have least-privilege, read-only grants. The transaction
    mode is defense in depth and deliberately fails closed when it cannot be established.
    """

    __slots__ = ("_connect_timeout", "_max_sample_rows", "_statement_timeout_ms")

    def __init__(
        self,
        connection_spec: DatabaseConnectionSpec,
        *,
        connect_timeout: float = 5.0,
        statement_timeout: float = 10.0,
        max_sample_rows: int = 100,
    ) -> None:
        if connection_spec.engine is not DatabaseEngine.ORACLE:
            raise DatabaseAdapterError("Oracle adapter requires an Oracle connection")
        if connection_spec.driver not in (None, "oracledb"):
            raise DatabaseAdapterError("Oracle adapter requires the oracledb driver")
        self._validate_timeout(connect_timeout, "connect_timeout")
        if connect_timeout > _MAX_CONNECT_TIMEOUT_SECONDS:
            raise DatabaseAdapterError("connect_timeout exceeds the adapter maximum")
        self._validate_timeout(statement_timeout, "statement_timeout")
        timeout_ms = max(1, math.ceil(statement_timeout * 1000))
        if timeout_ms > _MAX_CALL_TIMEOUT_MS:
            raise DatabaseAdapterError("statement_timeout exceeds the oracledb maximum")
        if (
            isinstance(max_sample_rows, bool)
            or not isinstance(max_sample_rows, int)
            or max_sample_rows <= 0
        ):
            raise DatabaseAdapterError("max_sample_rows must be a positive integer")
        super().__init__(connection_spec)
        self._connection_options()  # Validate every URI component without connecting.
        self._connect_timeout = connect_timeout
        self._statement_timeout_ms = timeout_ms
        self._max_sample_rows = max_sample_rows

    async def get_server_info(self) -> DatabaseServerInfo:
        rows, _ = await self._fetch(
            "get_server_info",
            """SELECT version, SYS_CONTEXT('USERENV', 'SERVICE_NAME')
            FROM product_component_version
            WHERE product LIKE 'Oracle Database%'
            FETCH FIRST 1 ROW ONLY""",
        )
        if not rows:
            raise DatabaseOperationError("Oracle operation 'get_server_info' failed")
        version, database = rows[0]
        return DatabaseServerInfo(
            engine=DatabaseEngine.ORACLE,
            version=str(version) if version is not None else None,
            database=str(database) if database is not None else None,
        )

    async def list_schemas(self) -> tuple[str, ...]:
        rows, _ = await self._fetch(
            "list_schemas",
            """SELECT u.username
            FROM all_users u
            WHERE u.oracle_maintained = 'N'
              AND (EXISTS (SELECT 1 FROM all_tables t WHERE t.owner = u.username)
                OR EXISTS (SELECT 1 FROM all_views v WHERE v.owner = u.username))
            ORDER BY u.username""",
        )
        return tuple(str(row[0]) for row in rows)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        _quote_identifier(schema)
        rows, _ = await self._fetch(
            "list_tables",
            """SELECT object_name, object_type
            FROM (
                SELECT table_name AS object_name, 'table' AS object_type
                FROM all_tables WHERE owner = :owner
                UNION ALL
                SELECT view_name AS object_name, 'view' AS object_type
                FROM all_views WHERE owner = :owner
            )
            ORDER BY object_name, object_type""",
            {"owner": schema},
        )
        return tuple(
            TableInfo(schema_name=schema, table_name=str(name), table_type=str(kind))
            for name, kind in rows
        )

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        _quote_identifier(schema)
        _quote_identifier(table)
        rows, _ = await self._fetch(
            "describe_table",
            """SELECT c.column_name, c.data_type, c.nullable, c.data_length,
                c.data_precision, c.data_scale, c.char_length, c.char_used,
                CASE WHEN EXISTS (
                    SELECT 1
                    FROM all_constraints pk
                    JOIN all_cons_columns pcc
                      ON pcc.owner = pk.owner
                     AND pcc.constraint_name = pk.constraint_name
                     AND pcc.table_name = pk.table_name
                    WHERE pk.constraint_type = 'P'
                      AND pk.owner = c.owner
                      AND pk.table_name = c.table_name
                      AND pcc.column_name = c.column_name
                ) THEN 1 ELSE 0 END
            FROM all_tab_columns c
            WHERE c.owner = :owner AND c.table_name = :table_name
            ORDER BY c.column_id""",
            {"owner": schema, "table_name": table},
        )
        if not rows:
            raise DatabaseObjectNotFoundError(
                "Oracle operation 'describe_table' found no visible object"
            )
        return TableDescription(
            schema_name=schema,
            table_name=table,
            columns=tuple(
                ColumnInfo(
                    name=str(name),
                    data_type=_format_oracle_type(
                        data_type, (data_length, precision, scale, char_length, char_used)
                    ),
                    nullable=nullable == "Y",
                    primary_key=bool(primary_key),
                )
                for (
                    name,
                    data_type,
                    nullable,
                    data_length,
                    precision,
                    scale,
                    char_length,
                    char_used,
                    primary_key,
                ) in rows
            ),
        )

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[RelationshipInfo, ...]:
        _quote_identifier(schema)
        if table is not None:
            _quote_identifier(table)
        rows, _ = await self._fetch(
            "get_relationships",
            """SELECT src.owner, src.table_name, src_col.column_name,
                target.owner, target.table_name, target_col.column_name,
                src.constraint_name
            FROM all_constraints src
            JOIN all_cons_columns src_col
              ON src_col.owner = src.owner
             AND src_col.constraint_name = src.constraint_name
             AND src_col.table_name = src.table_name
            JOIN all_constraints target
              ON target.owner = src.r_owner
             AND target.constraint_name = src.r_constraint_name
            JOIN all_cons_columns target_col
              ON target_col.owner = target.owner
             AND target_col.constraint_name = target.constraint_name
             AND target_col.table_name = target.table_name
             AND target_col.position = src_col.position
            WHERE src.constraint_type = 'R'
              AND ((src.owner = :schema AND :table_name IS NULL)
                OR (:table_name IS NOT NULL
                  AND ((src.owner = :schema AND src.table_name = :table_name)
                    OR (target.owner = :schema AND target.table_name = :table_name))))
            ORDER BY src.owner, src.table_name, src.constraint_name,
                src_col.position, target.owner, target.table_name""",
            {"schema": schema, "table_name": table},
        )
        return tuple(
            RelationshipInfo(
                source_schema=str(source_owner),
                source_table=str(source_table),
                source_column=str(source_column),
                target_schema=str(target_owner),
                target_table=str(target_table),
                target_column=str(target_column),
                constraint_name=str(constraint_name),
            )
            for (
                source_owner,
                source_table,
                source_column,
                target_owner,
                target_table,
                target_column,
                constraint_name,
            ) in rows
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        query = f"SELECT COUNT(*) FROM {_quote_identifier(schema)}.{_quote_identifier(table)}"  # noqa: S608 - identifiers are safely quoted
        rows, _ = await self._fetch("get_row_count", query)
        return int(rows[0][0])

    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: tuple[str, ...] | None = None,
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
        # The row limit is derived only from a validated integer, never caller-controlled text.
        query = (
            f"SELECT {selected} FROM {quoted_schema}.{quoted_table} "  # noqa: S608
            f"FETCH FIRST {limit + 1} ROWS ONLY"
        )
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
        params: Mapping[str, object] | None = None,
    ) -> tuple[list[tuple[Any, ...]], tuple[str, ...]]:
        connection: oracledb.AsyncConnection | None = None
        cursor: oracledb.AsyncCursor | None = None
        try:
            connection = await self._connect()
            connection.autocommit = False
            connection.call_timeout = self._statement_timeout_ms
            cursor = connection.cursor()
            await cursor.execute(_READ_ONLY_SQL)
            await cursor.execute(query, params)
            rows = [tuple(row) for row in await cursor.fetchall()]
            names = tuple(column.name for column in (cursor.description or ()))
        except (oracledb.Error, OSError) as error:
            if (
                operation == "describe_table"
                and isinstance(error, oracledb.DatabaseError)
                and _error_code(error) in _NOT_FOUND_OR_INACCESSIBLE_CODES
            ):
                raise DatabaseObjectNotFoundError(
                    "Oracle operation 'describe_table' found no visible object"
                ) from None
            raise DatabaseOperationError(f"Oracle operation '{operation}' failed") from None
        else:
            return rows, names
        finally:
            if connection is not None:
                with suppress(oracledb.Error, OSError):
                    await connection.rollback()
                if cursor is not None:
                    with suppress(oracledb.Error, OSError):
                        cursor.close()
                with suppress(oracledb.Error, OSError):
                    await connection.close()

    async def _connect(self) -> oracledb.AsyncConnection:
        """Acquire a private Thin-mode connection using credential-safe keyword arguments."""
        return cast(
            "oracledb.AsyncConnection",
            await oracledb.connect_async(
                **self._connection_options(), tcp_connect_timeout=self._connect_timeout
            ),
        )

    def _connection_options(self) -> dict[str, object]:
        raw = self._connection_spec.raw_connection_string.get_secret_value()
        try:
            parsed = urlsplit(raw)
            port = _DEFAULT_PORT if parsed.port is None else parsed.port
            host = parsed.hostname
            encoded_user = parsed.username
            user = unquote(encoded_user) if encoded_user is not None else ""
            password = unquote(parsed.password or "")
            service_name = unquote(parsed.path[1:]) if parsed.path.startswith("/") else ""
        except (UnicodeError, ValueError):
            raise DatabaseAdapterError("Invalid Oracle connection components") from None
        if (
            parsed.scheme.casefold() not in ("oracle", "oracle+oracledb")
            or not host
            or not user
            or not service_name
            or any("\x00" in value for value in (host, user, password, service_name))
            or parsed.query
            or parsed.fragment
            or not 1 <= port <= _MAX_PORT
        ):
            raise DatabaseAdapterError("Invalid Oracle connection components")
        return {
            "user": user,
            "password": password,
            "host": host,
            "port": port,
            "service_name": service_name,
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
