"""Immutable contracts for agent orchestration, safe tools, and execution results."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MAX_PROMPT_LENGTH: int = 10_000
_MAX_IDENTIFIER_LENGTH: int = 256
_MAX_SUMMARY_LENGTH: int = 20_000
_MAX_SAMPLE_ROWS_LIMIT: int = 25
_MAX_SAMPLE_COLUMNS_LIMIT: int = 128
_ASCII_CONTROL_LIMIT: int = 32
_ASCII_DEL: int = 127
_SQL_INJECTION_PUNCTUATION: tuple[str, ...] = (";", "--", "/*", "*/")


def is_valid_database_identifier_syntax(value: str) -> bool:
    """Validate database identifier syntax.

    Permits legitimate SQL identifiers including spaces, Unicode letters/numbers,
    hyphens, dots, underscores, and dollar signs, while strictly forbidding
    SQL injection tokens (';', '--', '/*'), single quotes, and control characters.
    """
    if not (1 <= len(value) <= _MAX_IDENTIFIER_LENGTH):
        return False
    if any(ord(c) < _ASCII_CONTROL_LIMIT or ord(c) == _ASCII_DEL for c in value):
        return False
    if any(punct in value for punct in _SQL_INJECTION_PUNCTUATION):
        return False
    return "'" not in value


class _FrozenOrchestrationModel(BaseModel):
    """Base model enforcing immutability and secret-safe error handling."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )


class DatabaseAgentRequest(_FrozenOrchestrationModel):
    """Bounded, validated user request for database understanding workflow."""

    user_prompt: str = Field(min_length=1, max_length=_MAX_PROMPT_LENGTH)
    schema_filter: str | None = Field(default=None, max_length=_MAX_IDENTIFIER_LENGTH)
    table_filter: str | None = Field(default=None, max_length=_MAX_IDENTIFIER_LENGTH)
    max_sample_rows: int = Field(default=10, ge=1, le=_MAX_SAMPLE_ROWS_LIMIT)
    max_sample_columns: int = Field(default=32, ge=1, le=_MAX_SAMPLE_COLUMNS_LIMIT)

    @field_validator("user_prompt")
    @classmethod
    def _validate_user_prompt(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("user_prompt must not be empty or whitespace only")
        if "\x00" in trimmed:
            raise ValueError("user_prompt must not contain NUL bytes")
        return trimmed

    @field_validator("schema_filter", "table_filter")
    @classmethod
    def _validate_filters(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            return None
        if not is_valid_database_identifier_syntax(trimmed):
            raise ValueError("Identifier filter contains invalid characters")
        return trimmed


class SafeServerInfo(_FrozenOrchestrationModel):
    """Sanitized database server metadata containing no credentials or host details."""

    engine: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    version: str | None = Field(default=None, max_length=_MAX_IDENTIFIER_LENGTH)
    database: str | None = Field(default=None, max_length=_MAX_IDENTIFIER_LENGTH)


class SafeTableInfo(_FrozenOrchestrationModel):
    """Sanitized table metadata."""

    schema_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_type: str = Field(default="table", max_length=64)

    @field_validator("table_type")
    @classmethod
    def _validate_table_type(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed or not is_valid_database_identifier_syntax(trimmed):
            raise ValueError("Invalid table_type")
        return trimmed


class SafeColumnInfo(_FrozenOrchestrationModel):
    """Sanitized column metadata."""

    name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    data_type: str = Field(max_length=64)
    nullable: bool | None = None
    primary_key: bool = False
    default_value: str | None = Field(default=None, max_length=512)
    comment: str | None = Field(default=None, max_length=512)


class SafeTableDescription(_FrozenOrchestrationModel):
    """Sanitized column-level table schema."""

    schema_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    columns: tuple[SafeColumnInfo, ...]

    @field_validator("schema_name", "table_name")
    @classmethod
    def _validate_identifiers(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed or not is_valid_database_identifier_syntax(trimmed):
            raise ValueError("Invalid identifier")
        return trimmed


class SafeRelationshipInfo(_FrozenOrchestrationModel):
    """Sanitized relationship metadata."""

    source_schema: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    source_table: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    source_column: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_schema: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_table: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_column: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    constraint_name: str | None = Field(default=None, max_length=_MAX_IDENTIFIER_LENGTH)


class SafeRowCountResult(_FrozenOrchestrationModel):
    """Safe table row count."""

    schema_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    row_count: int = Field(ge=0)


type SafeScalar = bool | int | float | str | None


class SafeSampleResponse(_FrozenOrchestrationModel):
    """Model-visible response carrying sanitized, leakage-validated sample rows.

    This model is constructed ONLY after passing Phase 3E sanitization, Phase 3F leakage
    validation, and mandatory final prompt-boundary revalidation.
    """

    status: Literal["success", "rejected", "error"]
    message: str = Field(max_length=1_000)
    schema_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    columns: tuple[str, ...] = Field(default_factory=tuple)
    rows: tuple[tuple[SafeScalar, ...], ...] = Field(default_factory=tuple, repr=False)
    row_count: int = Field(default=0, ge=0)
    truncated: bool = False
    policy_version: str = Field(default="", max_length=64)
    validator_version: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def _validate_shape(self) -> Self:
        if self.status == "success":
            if self.row_count != len(self.rows):
                raise ValueError("row_count must equal number of sample rows")
            if any(len(row) != len(self.columns) for row in self.rows):
                raise ValueError("each row must match column count")
        elif self.rows:
            raise ValueError("rejected or errored response must have empty rows")
        return self


class TableSummary(_FrozenOrchestrationModel):
    """Structured summary of an inspected database table."""

    schema_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    table_name: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    column_count: int = Field(ge=0)
    row_count: int | None = Field(default=None, ge=0)
    primary_keys: tuple[str, ...] = Field(default_factory=tuple)
    columns: tuple[str, ...] = Field(default_factory=tuple)
    sample_row_count: int = Field(default=0, ge=0)
    sample_preview: tuple[dict[str, SafeScalar], ...] = Field(default_factory=tuple, repr=False)


class DatabaseRelationshipSummary(_FrozenOrchestrationModel):
    """Structured summary of relationships discovered between tables."""

    source_schema: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    source_table: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    source_column: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_schema: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_table: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    target_column: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)


class DatabaseUnderstandingResponse(_FrozenOrchestrationModel):
    """Top-level structured response from the Phase 4 database understanding agent."""

    summary: str = Field(max_length=_MAX_SUMMARY_LENGTH)
    tables: tuple[TableSummary, ...] = Field(default_factory=tuple)
    relationships: tuple[DatabaseRelationshipSummary, ...] = Field(default_factory=tuple)
    security_notes: tuple[str, ...] = Field(default_factory=tuple)
    can_fulfill: bool = True


@dataclass(slots=True)
class AgentExecutionContext:
    """Run-specific execution context and audit tracker."""

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: DatabaseAgentRequest = field(
        default_factory=lambda: DatabaseAgentRequest(user_prompt="default")
    )
    audit_events: list[str] = field(default_factory=list)
    security_violations: list[str] = field(default_factory=list)

    def record_audit(self, event: str) -> None:
        """Record an audit event without secrets."""
        if "\x00" not in event:
            self.audit_events.append(event[:256])

    def record_security_violation(self, violation: str) -> None:
        """Record a security violation code."""
        if "\x00" not in violation:
            self.security_violations.append(violation[:256])


class SafeAgentUsage(_FrozenOrchestrationModel):
    """Non-sensitive resource usage summary."""

    requests: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class DatabaseAgentRunResult(_FrozenOrchestrationModel):
    """Complete execution result of one agent invocation."""

    run_id: str = Field(max_length=64)
    response: DatabaseUnderstandingResponse
    usage: SafeAgentUsage
    audit_events: tuple[str, ...] = Field(default_factory=tuple)
