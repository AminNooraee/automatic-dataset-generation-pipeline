"""Tests for the database adapter contract and dependency-injected factory."""

from typing import TYPE_CHECKING, cast

import pytest

from automatic_dataset_generation.database import (
    ColumnInfo,
    DatabaseAdapter,
    DatabaseAdapterError,
    DatabaseAdapterFactory,
    DatabaseAdapterNotRegisteredError,
    DatabaseConnectionSpec,
    DatabaseEngine,
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
    parse_connection_string,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


EXPECTED_EVENT_ROW_COUNT = 12


class FakeDatabaseAdapter(DatabaseAdapter):
    """Minimal in-memory implementation used only to exercise the contract."""

    def received_spec(self, expected: DatabaseConnectionSpec) -> bool:
        return self._connection_spec is expected

    async def get_server_info(self) -> DatabaseServerInfo:
        return DatabaseServerInfo(
            engine=self._connection_spec.engine,
            version="synthetic-version",
            database="synthetic-database",
        )

    async def list_schemas(self) -> tuple[str, ...]:
        return ("public",)

    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        return (TableInfo(schema_name=schema, table_name="events"),)

    async def describe_table(self, schema: str, table: str) -> TableDescription:
        return TableDescription(
            schema_name=schema,
            table_name=table,
            columns=(ColumnInfo(name="event_id", data_type="bigint"),),
        )

    async def get_relationships(
        self,
        schema: str,
        table: str | None = None,
    ) -> tuple[RelationshipInfo, ...]:
        source_table = table or "events"
        return (
            RelationshipInfo(
                source_schema=schema,
                source_table=source_table,
                source_column="account_id",
                target_schema=schema,
                target_table="accounts",
                target_column="account_id",
            ),
        )

    async def get_row_count(self, schema: str, table: str) -> int:
        return len(schema) + len(table)

    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: tuple[str, ...] | None = None,
    ) -> SampleResult:
        selected_columns = columns or ("event_id",)
        return SampleResult(
            schema_name=schema,
            table_name=table,
            columns=selected_columns,
            rows=((1,) * len(selected_columns),) if limit else (),
            row_count=1 if limit else 0,
            truncated=limit == 1,
        )


def _postgresql_spec(marker: str = "synthetic-phase2b-marker") -> DatabaseConnectionSpec:
    return parse_connection_string(f"postgresql://synthetic-user:{marker}@host/database")


def _fake_builder(connection_spec: DatabaseConnectionSpec) -> DatabaseAdapter:
    return FakeDatabaseAdapter(connection_spec)


def test_database_adapter_is_abstract() -> None:
    adapter_type = cast("type[object]", DatabaseAdapter)

    with pytest.raises(TypeError, match="abstract"):
        adapter_type()


@pytest.mark.asyncio
async def test_fake_adapter_satisfies_async_contract() -> None:
    adapter = FakeDatabaseAdapter(_postgresql_spec())

    assert await adapter.get_server_info() == DatabaseServerInfo(
        engine=DatabaseEngine.POSTGRESQL,
        version="synthetic-version",
        database="synthetic-database",
    )
    assert await adapter.list_schemas() == ("public",)
    assert await adapter.list_tables("public") == (
        TableInfo(schema_name="public", table_name="events"),
    )
    assert (await adapter.describe_table("public", "events")).table_name == "events"
    assert (await adapter.get_relationships("public", "events"))[0].source_table == "events"
    assert await adapter.get_row_count("public", "events") == EXPECTED_EVENT_ROW_COUNT
    assert (await adapter.sample_rows("public", "events", columns=("event_id",))).row_count == 1


def test_adapter_contract_exposes_only_allowlisted_operations() -> None:
    allowed_operations = {
        "describe_table",
        "get_relationships",
        "get_row_count",
        "get_server_info",
        "list_schemas",
        "list_tables",
        "sample_rows",
    }
    forbidden_operations = {
        "execute",
        "execute_sql",
        "query",
        "raw_query",
        "run_any_sql",
        "run_sql",
    }

    assert allowed_operations.issubset(dir(DatabaseAdapter))
    assert forbidden_operations.isdisjoint(dir(DatabaseAdapter))


def test_adapter_representation_does_not_disclose_connection_data() -> None:
    marker = "synthetic-phase2b-secret-marker"
    adapter = FakeDatabaseAdapter(_postgresql_spec(marker))

    assert repr(adapter) == "FakeDatabaseAdapter(engine='postgresql')"
    assert marker not in repr(adapter)
    assert marker not in str(adapter)


def test_factory_creates_registered_adapter_with_original_spec() -> None:
    received_specs: list[DatabaseConnectionSpec] = []

    def builder(connection_spec: DatabaseConnectionSpec) -> DatabaseAdapter:
        received_specs.append(connection_spec)
        return FakeDatabaseAdapter(connection_spec)

    factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: builder})
    connection_spec = parse_connection_string("postgres://synthetic-user@host/database")

    adapter = factory.create(connection_spec)

    assert isinstance(adapter, FakeDatabaseAdapter)
    assert adapter.received_spec(connection_spec)
    assert received_specs == [connection_spec]


def test_factory_copies_caller_registration_mapping() -> None:
    builders: dict[DatabaseEngine, Callable[[DatabaseConnectionSpec], DatabaseAdapter]] = {
        DatabaseEngine.POSTGRESQL: _fake_builder
    }
    factory = DatabaseAdapterFactory(builders)
    builders.clear()

    assert isinstance(factory.create(_postgresql_spec()), FakeDatabaseAdapter)


def test_factory_instances_have_independent_registrations() -> None:
    registered_factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: _fake_builder})
    empty_builders: Mapping[
        DatabaseEngine, Callable[[DatabaseConnectionSpec], DatabaseAdapter]
    ] = {}
    empty_factory = DatabaseAdapterFactory(empty_builders)

    assert isinstance(registered_factory.create(_postgresql_spec()), FakeDatabaseAdapter)
    with pytest.raises(DatabaseAdapterNotRegisteredError):
        empty_factory.create(_postgresql_spec())


def test_unregistered_engine_error_is_secret_safe() -> None:
    marker = "synthetic-phase2b-secret-marker"
    connection_spec = parse_connection_string(f"mysql://synthetic-user:{marker}@host/database")
    factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: _fake_builder})

    with pytest.raises(DatabaseAdapterNotRegisteredError) as error:
        factory.create(connection_spec)

    assert str(error.value) == "No database adapter is registered for engine 'mysql'"
    assert marker not in str(error.value)
    assert marker not in repr(error.value)


def test_builder_failure_is_wrapped_without_secret_disclosure() -> None:
    marker = "synthetic-phase2b-secret-marker"
    connection_spec = _postgresql_spec(marker)

    def failing_builder(spec: DatabaseConnectionSpec) -> DatabaseAdapter:
        raise RuntimeError(spec.raw_connection_string.get_secret_value())

    factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: failing_builder})

    with pytest.raises(DatabaseAdapterError) as error:
        factory.create(connection_spec)

    assert str(error.value) == "Database adapter creation failed for engine 'postgresql'"
    assert marker not in str(error.value)
    assert marker not in repr(error.value)
    assert error.value.__suppress_context__ is True


def test_factory_rejects_builder_returning_non_adapter() -> None:
    def invalid_builder(_connection_spec: DatabaseConnectionSpec) -> DatabaseAdapter:
        return cast("DatabaseAdapter", object())

    factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: invalid_builder})

    with pytest.raises(DatabaseAdapterError, match="creation failed for engine 'postgresql'"):
        factory.create(_postgresql_spec())


def test_factory_representation_contains_only_engine_names() -> None:
    marker = "synthetic-phase2b-secret-marker"
    factory = DatabaseAdapterFactory({DatabaseEngine.POSTGRESQL: _fake_builder})

    rendered_values = (repr(factory), str(factory))

    assert repr(factory) == "DatabaseAdapterFactory(registered_engines=('postgresql',))"
    assert all(marker not in rendered for rendered in rendered_values)
