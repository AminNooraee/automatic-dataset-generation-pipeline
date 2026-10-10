"""Read-only PostgreSQL implementation of the database adapter contract."""

from __future__ import annotations

import math
from contextlib import suppress
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

import psycopg
from psycopg import sql

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

_READ_ONLY_SQL = "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
_SET_TIMEOUT_SQL = "SELECT set_config('statement_timeout', %s, false)"


class PostgreSQLAdapter(DatabaseAdapter):
    """Bounded, read-only PostgreSQL access using one async connection per operation.

    The configured role must remain least-privilege and read-only; session configuration is defense
    in depth, not an authorization replacement.
    """

    __slots__ = ("_connect_timeout", "_max_sample_rows", "_statement_timeout")

    def __init__(
        self,
        connection_spec: DatabaseConnectionSpec,
        *,
        connect_timeout: float = 5.0,
        statement_timeout: float = 10.0,
        max_sample_rows: int = 100,
    ) -> None:
        if connection_spec.engine is not DatabaseEngine.POSTGRESQL:
            raise DatabaseAdapterError("PostgreSQL adapter requires a PostgreSQL connection")
        if connection_spec.driver not in (None, "psycopg"):
            raise DatabaseAdapterError("PostgreSQL adapter requires the psycopg driver")
        self._validate_timeout(connect_timeout, "connect_timeout")
        self._validate_timeout(statement_timeout, "statement_timeout")
        if (
            isinstance(max_sample_rows, bool)
            or not isinstance(max_sample_rows, int)
            or max_sample_rows <= 0
        ):
            raise DatabaseAdapterError("max_sample_rows must be a positive integer")
        super().__init__(connection_spec)
        self._connect_timeout = connect_timeout
        self._statement_timeout = statement_timeout
        self._max_sample_rows = max_sample_rows

    async def get_server_info(self) -> DatabaseServerInfo:
        rows, _ = await self._fetch("get_server_info", "SELECT version(), current_database()")
        version, database = rows[0]
        return DatabaseServerInfo(
            engine=DatabaseEngine.POSTGRESQL, version=str(version), database=str(database)
        )

    async def list_schemas(self) -> tuple[str, ...]:
        rows, _ = await self._fetch(
            "list_schemas",
            """SELECT nspname FROM pg_namespace
            WHERE nspname <> 'information_schema' AND left(nspname, 3) <> 'pg_'
              AND has_schema_privilege(oid, 'USAGE') ORDER BY nspname""",
        )
        return tuple(str(row[0]) for row in rows)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        self._identifier(schema, "schema")
        rows, _ = await self._fetch(
            "list_tables",
            """SELECT table_name, table_type
            FROM information_schema.tables WHERE table_schema = %s
            AND table_type IN ('BASE TABLE', 'VIEW') ORDER BY table_name""",
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
        self._identifier(schema, "schema")
        self._identifier(table, "table")
        rows, _ = await self._fetch(
            "describe_table",
            """SELECT attribute.attname,
            pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
            NOT attribute.attnotnull,
            EXISTS (
                SELECT 1 FROM pg_constraint AS pk
                WHERE pk.conrelid = relation.oid AND pk.contype = 'p'
                  AND attribute.attnum = ANY (pk.conkey)
            )
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            LEFT JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
              AND attribute.attnum > 0 AND NOT attribute.attisdropped
            WHERE namespace.nspname = %s AND relation.relname = %s
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND has_schema_privilege(namespace.oid, 'USAGE')
              AND has_table_privilege(relation.oid, 'SELECT')
            ORDER BY attribute.attnum""",
            (schema, table),
        )
        if not rows:
            raise DatabaseObjectNotFoundError(
                "PostgreSQL operation 'describe_table' found no visible object"
            )
        return TableDescription(
            schema_name=schema,
            table_name=table,
            columns=tuple(
                ColumnInfo(
                    name=str(name),
                    data_type=str(data_type),
                    nullable=nullable,
                    primary_key=bool(pk),
                )
                for name, data_type, nullable, pk in rows
                if name is not None
            ),
        )

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[RelationshipInfo, ...]:
        self._identifier(schema, "schema")
        if table is not None:
            self._identifier(table, "table")
        query = """SELECT source_namespace.nspname, source_class.relname, source_attr.attname,
            target_namespace.nspname, target_class.relname, target_attr.attname, con.conname
            FROM pg_constraint AS con
            JOIN pg_class AS source_class ON source_class.oid = con.conrelid
            JOIN pg_namespace AS source_namespace
              ON source_namespace.oid = source_class.relnamespace
            JOIN pg_class AS target_class ON target_class.oid = con.confrelid
            JOIN pg_namespace AS target_namespace
              ON target_namespace.oid = target_class.relnamespace
            JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY
              AS key_pair(source_attnum, target_attnum, position) ON true
            JOIN pg_attribute AS source_attr ON source_attr.attrelid = con.conrelid
              AND source_attr.attnum = key_pair.source_attnum
            JOIN pg_attribute AS target_attr ON target_attr.attrelid = con.confrelid
              AND target_attr.attnum = key_pair.target_attnum
            WHERE con.contype = 'f' AND has_table_privilege(con.conrelid, 'SELECT')
              AND has_table_privilege(con.confrelid, 'SELECT')
              AND ((source_namespace.nspname = %s AND %s::text IS NULL)
                OR (%s::text IS NOT NULL AND ((source_namespace.nspname = %s
                  AND source_class.relname = %s) OR (target_namespace.nspname = %s
                  AND target_class.relname = %s))))
            ORDER BY source_namespace.nspname, source_class.relname, con.conname, key_pair.position,
              target_namespace.nspname, target_class.relname"""
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
        self._identifier(schema, "schema")
        self._identifier(table, "table")
        rows, _ = await self._fetch(
            "get_row_count",
            sql.SQL("SELECT count(*) FROM {}.{}").format(
                sql.Identifier(schema), sql.Identifier(table)
            ),
        )
        return int(rows[0][0])

    async def sample_rows(
        self, schema: str, table: str, limit: int = 10, columns: tuple[str, ...] | None = None
    ) -> SampleResult:
        self._identifier(schema, "schema")
        self._identifier(table, "table")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self._max_sample_rows
        ):
            raise DatabaseAdapterError("sample limit must be between 1 and the configured maximum")
        if columns is not None and not columns:
            raise DatabaseAdapterError("columns must not be empty")
        if columns is not None:
            for column in columns:
                self._identifier(column, "column")
        selected = (
            sql.SQL("*") if columns is None else sql.SQL(", ").join(map(sql.Identifier, columns))
        )
        query = sql.SQL("SELECT {} FROM {}.{} LIMIT %s").format(
            selected, sql.Identifier(schema), sql.Identifier(table)
        )
        rows, names = await self._fetch("sample_rows", query, (limit + 1,))
        returned = tuple(tuple(row) for row in rows[:limit])
        return SampleResult(
            schema_name=schema,
            table_name=table,
            columns=names,
            rows=returned,
            row_count=len(returned),
            truncated=len(rows) > limit,
        )

    async def _fetch(
        self, operation: str, query: Any, params: Sequence[Any] = ()
    ) -> tuple[list[tuple[Any, ...]], tuple[str, ...]]:
        connection: psycopg.AsyncConnection[Any] | None = None
        try:
            connection = await self._connect()
            async with connection.cursor() as cursor:
                await cursor.execute(_READ_ONLY_SQL)
                await cursor.execute(_SET_TIMEOUT_SQL, (str(self._timeout_milliseconds()),))
                await cursor.execute(query, params)
                rows = [tuple(row) for row in await cursor.fetchall()]
                return rows, tuple(column.name for column in (cursor.description or ()))
        except DatabaseAdapterError:
            raise
        except psycopg.Error:
            raise DatabaseOperationError(f"PostgreSQL operation '{operation}' failed") from None
        finally:
            if connection is not None:
                # A close error cannot safely replace the operation result or prior safe error.
                with suppress(psycopg.Error):
                    await connection.close()

    async def _connect(self) -> psycopg.AsyncConnection[Any]:
        """Acquire one operation-scoped connection; a future pooling seam."""
        return await psycopg.AsyncConnection.connect(
            self._normalized_dsn(),
            connect_timeout=math.ceil(self._connect_timeout),
            autocommit=True,
        )

    def _normalized_dsn(self) -> str:
        dsn = self._connection_spec.raw_connection_string.get_secret_value()
        return "postgresql://" + dsn.partition("://")[2]

    def _timeout_milliseconds(self) -> int:
        return max(1, math.ceil(self._statement_timeout * 1000))

    @staticmethod
    def _validate_timeout(value: float, name: str) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise DatabaseAdapterError(f"{name} must be a positive finite number")

    @staticmethod
    def _identifier(value: str, name: str) -> None:
        if not isinstance(value, str) or not value:
            raise DatabaseAdapterError(f"{name} must be a non-empty identifier")
