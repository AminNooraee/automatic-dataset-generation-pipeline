"""Engine-neutral database metadata and trusted raw result contracts."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from automatic_dataset_generation.database.connection import DatabaseEngine


class _FrozenDatabaseModel(BaseModel):
    """Shared validation policy for immutable database contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class DatabaseServerInfo(_FrozenDatabaseModel):
    """Trusted server metadata returned by a database adapter.

    This model contains no credentials, but its metadata is not automatically approved for LLM
    exposure. That policy boundary belongs to the later sanitization phase.
    """

    engine: DatabaseEngine
    version: str | None = None
    database: str | None = None


class TableInfo(_FrozenDatabaseModel):
    """Vendor-neutral identity and type information for a database table."""

    schema_name: str
    table_name: str
    table_type: str = "table"


class ColumnInfo(_FrozenDatabaseModel):
    """Vendor-neutral database column metadata."""

    name: str
    data_type: str
    nullable: bool | None = None
    primary_key: bool = False


class TableDescription(_FrozenDatabaseModel):
    """Column-level description of a database table."""

    schema_name: str
    table_name: str
    columns: tuple[ColumnInfo, ...]


class RelationshipInfo(_FrozenDatabaseModel):
    """A vendor-neutral relationship between source and target columns."""

    source_schema: str
    source_table: str
    source_column: str
    target_schema: str
    target_table: str
    target_column: str
    constraint_name: str | None = None


class SampleResult(_FrozenDatabaseModel):
    """A bounded collection of trusted raw database rows.

    Row values are intentionally represented by ``object`` at the database boundary. They are raw,
    unsanitized data and must not be sent to LLM prompts, logs, telemetry, or artifacts. Concrete
    adapters must enforce a configured hard maximum and must never retrieve an uncontrolled table.

    ``row_count`` is the number of rows contained in this result, not the total number of rows in
    the source table. The total table row count is available separately through
    ``DatabaseAdapter.get_row_count()``.
    """

    schema_name: str
    table_name: str
    columns: tuple[str, ...]
    rows: tuple[tuple[object, ...], ...] = Field(repr=False)
    row_count: int = Field(ge=0)
    truncated: bool

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        """Require row metadata to describe exactly the bounded values returned."""
        if self.row_count != len(self.rows):
            raise ValueError("row_count must equal the number of sampled rows")
        if any(len(row) != len(self.columns) for row in self.rows):
            raise ValueError("Each sampled row must match the declared columns")
        return self
