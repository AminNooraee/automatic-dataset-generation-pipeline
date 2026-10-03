"""Dependency-injected database adapter selection."""

from collections.abc import Callable, Mapping
from types import MappingProxyType

from automatic_dataset_generation.database.adapter import DatabaseAdapter
from automatic_dataset_generation.database.connection import DatabaseConnectionSpec, DatabaseEngine
from automatic_dataset_generation.database.errors import (
    DatabaseAdapterError,
    DatabaseAdapterNotRegisteredError,
)

type AdapterBuilder = Callable[[DatabaseConnectionSpec], DatabaseAdapter]


class DatabaseAdapterFactory:
    """Create adapters from an isolated, constructor-supplied builder mapping."""

    __slots__ = ("_builders",)

    def __init__(self, builders: Mapping[DatabaseEngine, AdapterBuilder]) -> None:
        self._builders: Mapping[DatabaseEngine, AdapterBuilder] = MappingProxyType(dict(builders))

    def create(self, connection_spec: DatabaseConnectionSpec) -> DatabaseAdapter:
        """Create the registered adapter without opening a database connection."""
        builder = self._builders.get(connection_spec.engine)
        if builder is None:
            raise DatabaseAdapterNotRegisteredError(
                f"No database adapter is registered for engine {connection_spec.engine.value!r}"
            )

        try:
            adapter = builder(connection_spec)
        except Exception:  # noqa: BLE001 - redact arbitrary builder failures at this trust boundary.
            raise DatabaseAdapterError(
                f"Database adapter creation failed for engine {connection_spec.engine.value!r}"
            ) from None

        if not isinstance(adapter, DatabaseAdapter):
            raise DatabaseAdapterError(
                f"Database adapter creation failed for engine {connection_spec.engine.value!r}"
            )
        return adapter

    def __repr__(self) -> str:
        """Represent only the non-sensitive registered engine names."""
        return self._safe_representation()

    def __str__(self) -> str:
        """Render only the non-sensitive registered engine names."""
        return self._safe_representation()

    def _safe_representation(self) -> str:
        engines = tuple(sorted(engine.value for engine in self._builders))
        return f"{type(self).__name__}(registered_engines={engines!r})"
