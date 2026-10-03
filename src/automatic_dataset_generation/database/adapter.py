"""Engine-neutral asynchronous database adapter contract."""

from abc import ABC, abstractmethod

from automatic_dataset_generation.database.connection import DatabaseConnectionSpec
from automatic_dataset_generation.database.models import (
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
)


class DatabaseAdapter(ABC):
    """Allowlisted contract implemented by future relational database adapters.

    The connection specification is retained as protected trusted state. It is deliberately not
    exposed through a public property, and normal representations reveal only its normalized engine.
    """

    __slots__ = ("_connection_spec",)

    def __init__(self, connection_spec: DatabaseConnectionSpec) -> None:
        self._connection_spec = connection_spec

    def __repr__(self) -> str:
        """Represent the adapter without credentials or connection details."""
        return self._safe_representation()

    def __str__(self) -> str:
        """Render the adapter without credentials or connection details."""
        return self._safe_representation()

    def _safe_representation(self) -> str:
        return f"{type(self).__name__}(engine={self._connection_spec.engine.value!r})"

    @abstractmethod
    async def get_server_info(self) -> DatabaseServerInfo:
        """Return trusted metadata about the connected database server."""
        raise NotImplementedError

    @abstractmethod
    async def list_schemas(self) -> tuple[str, ...]:
        """Return schema names visible through the adapter's constrained access."""
        raise NotImplementedError

    @abstractmethod
    async def list_tables(self, schema: str) -> tuple[TableInfo, ...]:
        """Return tables in one explicitly named schema."""
        raise NotImplementedError

    @abstractmethod
    async def describe_table(self, schema: str, table: str) -> TableDescription:
        """Return column metadata for one explicitly identified table."""
        raise NotImplementedError

    @abstractmethod
    async def get_relationships(
        self,
        schema: str,
        table: str | None = None,
    ) -> tuple[RelationshipInfo, ...]:
        """Return relationships constrained to a schema and optional table."""
        raise NotImplementedError

    @abstractmethod
    async def get_row_count(self, schema: str, table: str) -> int:
        """Return the row count for one explicitly identified table."""
        raise NotImplementedError

    @abstractmethod
    async def sample_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: tuple[str, ...] | None = None,
    ) -> SampleResult:
        """Return bounded raw rows.

        Concrete adapters must enforce a configured hard maximum regardless of the requested limit
        and must never perform uncontrolled full-table retrieval.
        """
        raise NotImplementedError
