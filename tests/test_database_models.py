"""Tests for engine-neutral database metadata and result contracts."""

from datetime import date
from decimal import Decimal

import pytest
from pydantic import ValidationError

from automatic_dataset_generation.database import (
    ColumnInfo,
    DatabaseEngine,
    DatabaseServerInfo,
    RelationshipInfo,
    SampleResult,
    TableDescription,
    TableInfo,
)


def test_database_server_info_defaults() -> None:
    server_info = DatabaseServerInfo(engine=DatabaseEngine.POSTGRESQL)

    assert server_info.engine is DatabaseEngine.POSTGRESQL
    assert server_info.version is None
    assert server_info.database is None


def test_table_and_column_defaults() -> None:
    table = TableInfo(schema_name="public", table_name="events")
    column = ColumnInfo(name="event_id", data_type="bigint")

    assert table.table_type == "table"
    assert column.nullable is None
    assert column.primary_key is False


def test_table_description_uses_immutable_column_collection() -> None:
    columns = (
        ColumnInfo(
            name="event_id",
            data_type="bigint",
            nullable=False,
            primary_key=True,
        ),
    )
    description = TableDescription(
        schema_name="public",
        table_name="events",
        columns=columns,
    )

    assert description.columns == columns
    assert isinstance(description.columns, tuple)


def test_relationship_info_supports_optional_constraint_name() -> None:
    relationship = RelationshipInfo(
        source_schema="public",
        source_table="events",
        source_column="account_id",
        target_schema="public",
        target_table="accounts",
        target_column="account_id",
    )

    assert relationship.constraint_name is None


def test_sample_result_supports_realistic_scalar_values() -> None:
    rows = ((1, Decimal("12.50"), date(2026, 10, 3), None),)
    result = SampleResult(
        schema_name="public",
        table_name="events",
        columns=("event_id", "amount", "event_date", "note"),
        rows=rows,
        row_count=1,
        truncated=True,
    )

    assert result.rows == rows
    assert isinstance(result.rows, tuple)
    assert result.row_count == 1
    assert result.truncated is True


def test_sample_result_diagnostics_hide_rows_without_removing_access() -> None:
    marker = "synthetic-phase2b-raw-row-secret-marker"
    result = SampleResult(
        schema_name="public",
        table_name="events",
        columns=("sensitive_value",),
        rows=((marker,),),
        row_count=1,
        truncated=False,
    )

    assert marker not in repr(result)
    assert marker not in str(result)
    assert result.rows == ((marker,),)
    assert result.model_dump()["rows"] == ((marker,),)


def test_models_are_frozen() -> None:
    table = TableInfo(schema_name="public", table_name="events")
    field_name = "table_name"

    with pytest.raises(ValidationError, match="frozen"):
        setattr(table, field_name, "changed")


def test_models_reject_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TableInfo.model_validate(
            {
                "schema_name": "public",
                "table_name": "events",
                "vendor_flag": True,
            }
        )


def test_sample_result_rejects_incorrect_row_count() -> None:
    with pytest.raises(ValidationError, match="row_count must equal"):
        SampleResult(
            schema_name="public",
            table_name="events",
            columns=("event_id",),
            rows=((1,),),
            row_count=0,
            truncated=False,
        )


def test_sample_result_validation_errors_hide_raw_rows() -> None:
    marker = "synthetic-phase2b-validation-secret-marker"

    with pytest.raises(ValidationError) as error:
        SampleResult(
            schema_name="public",
            table_name="events",
            columns=("sensitive_value",),
            rows=((marker,),),
            row_count=0,
            truncated=False,
        )

    assert marker not in str(error.value)
    assert marker not in repr(error.value)


def test_sample_result_rejects_row_width_mismatch() -> None:
    with pytest.raises(ValidationError, match="must match the declared columns"):
        SampleResult(
            schema_name="public",
            table_name="events",
            columns=("event_id", "event_name"),
            rows=((1,),),
            row_count=1,
            truncated=False,
        )


def test_sample_result_rejects_negative_row_count() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        SampleResult(
            schema_name="public",
            table_name="events",
            columns=(),
            rows=(),
            row_count=-1,
            truncated=False,
        )
