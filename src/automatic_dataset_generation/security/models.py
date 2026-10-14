"""Immutable Phase 3A security and sanitized-data domain contracts."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_MAX_SOURCE_LENGTH = 128
_MAX_POLICY_VERSION_LENGTH = 64
_MAX_REASON_CODE_LENGTH = 64

type SanitizedValue = bool | int | float | str | None


class SensitivityClass(StrEnum):
    """Broad, stable data-sensitivity classification."""

    NON_SENSITIVE = "non_sensitive"
    PII = "pii"
    SECRET = "secret"  # noqa: S105  # pragma: allowlist secret - stable classification label, not secret material.
    CREDENTIAL = "credential"
    UNKNOWN = "unknown"


class SanitizationAction(StrEnum):
    """Transformation decision to be implemented by a later sanitization phase."""

    ALLOW = "allow"
    REDACT = "redact"
    MASK = "mask"
    PSEUDONYMIZE = "pseudonymize"
    DROP = "drop"


class _FrozenSecurityModel(BaseModel):
    """Shared immutable, low-disclosure validation policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class FieldReference(_FrozenSecurityModel):
    """Metadata-only identity of a relational field; it never contains a cell value."""

    schema_name: str
    table_name: str
    column_name: str

    @field_validator("schema_name", "table_name", "column_name")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        """Accept database identifiers without normalization while rejecting unsafe empties."""
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("field identifiers must be non-empty text without NUL")
        return value


class FieldClassification(_FrozenSecurityModel):
    """Safe-to-log field classification metadata with no raw or matched value."""

    field: FieldReference
    sensitivity: SensitivityClass
    confidence: float
    detector: str = Field(max_length=_MAX_SOURCE_LENGTH)

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence_type(cls, value: object) -> object:
        """Reject booleans/coercions and non-finite or out-of-range confidence values."""
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0.0 <= value <= 1.0
        ):
            raise ValueError("confidence must be a finite number from 0.0 through 1.0")
        return value

    @field_validator("detector")
    @classmethod
    def validate_detector(cls, value: str) -> str:
        """Require a short source identifier rather than free-form diagnostic text."""
        if not value or "\x00" in value:
            raise ValueError("detector must be non-empty text without NUL")
        return value


class SanitizationDecision(_FrozenSecurityModel):
    """Metadata-only policy decision; transformation material and raw values are excluded."""

    field: FieldReference
    sensitivity: SensitivityClass
    action: SanitizationAction
    policy_version: str = Field(max_length=_MAX_POLICY_VERSION_LENGTH)
    reason_code: str = Field(max_length=_MAX_REASON_CODE_LENGTH, pattern=r"^[a-z][a-z0-9_.-]*$")

    @field_validator("policy_version")
    @classmethod
    def validate_policy_version(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("policy_version must be non-empty text without NUL")
        return value

    @model_validator(mode="after")
    def validate_fail_closed_action(self) -> Self:
        """Prevent sensitive or unknown classifications from being allowed directly."""
        if (
            self.sensitivity is not SensitivityClass.NON_SENSITIVE
            and self.action is SanitizationAction.ALLOW
        ):
            raise ValueError("action is not permitted for this sensitivity")
        return self


class SanitizedSample(_FrozenSecurityModel):
    """LLM-eligible data contract for later sanitizers to construct and leakage-check.

    Phase 3A defines and validates this boundary but performs no sanitization itself.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )

    schema_name: str
    table_name: str
    columns: tuple[str, ...]
    rows: tuple[tuple[SanitizedValue, ...], ...] = Field(repr=False)
    row_count: int = Field(ge=0)
    truncated: bool
    policy_version: str = Field(max_length=_MAX_POLICY_VERSION_LENGTH)

    @field_validator("schema_name", "table_name", "policy_version")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("metadata text must be non-empty and contain no NUL")
        return value

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, columns: tuple[str, ...]) -> tuple[str, ...]:
        if any(not column or "\x00" in column for column in columns):
            raise ValueError("column names must be non-empty and contain no NUL")
        if len(set(columns)) != len(columns):
            raise ValueError("column names must be unique")
        return columns

    @field_validator("rows", mode="before")
    @classmethod
    def validate_exact_value_domain(cls, rows: object) -> object:
        """Reject values Pydantic could otherwise coerce into an allowed scalar type."""
        if isinstance(rows, tuple):
            for row in rows:
                if isinstance(row, tuple) and any(
                    value is not None and type(value) not in (bool, int, float, str)
                    for value in row
                ):
                    raise ValueError("sanitized rows contain an unsupported value type")
        return rows

    @model_validator(mode="after")
    def validate_shape_and_values(self) -> Self:
        if self.row_count != len(self.rows):
            raise ValueError("row_count must equal the number of sanitized rows")
        if any(len(row) != len(self.columns) for row in self.rows):
            raise ValueError("Each sanitized row must match the declared columns")
        if any(
            isinstance(value, float) and not math.isfinite(value)
            for row in self.rows
            for value in row
        ):
            raise ValueError("sanitized floating-point values must be finite")
        return self


class SanitizationReport(_FrozenSecurityModel):
    """Non-sensitive audit summary containing counts and policy lineage only."""

    policy_version: str = Field(max_length=_MAX_POLICY_VERSION_LENGTH)
    total_fields: int = Field(ge=0, strict=True)
    classified_fields: int = Field(ge=0, strict=True)
    redacted_fields: int = Field(default=0, ge=0, strict=True)
    masked_fields: int = Field(default=0, ge=0, strict=True)
    pseudonymized_fields: int = Field(default=0, ge=0, strict=True)
    dropped_fields: int = Field(default=0, ge=0, strict=True)
    allowed_fields: int = Field(default=0, ge=0, strict=True)
    unknown_fields: int = Field(default=0, ge=0, strict=True)

    @field_validator("policy_version")
    @classmethod
    def validate_policy_version(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("policy_version must be non-empty text without NUL")
        return value

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        action_total = (
            self.redacted_fields
            + self.masked_fields
            + self.pseudonymized_fields
            + self.dropped_fields
            + self.allowed_fields
        )
        if self.classified_fields > self.total_fields or action_total != self.classified_fields:
            raise ValueError("sanitization report counts are inconsistent")
        if self.unknown_fields > self.classified_fields:
            raise ValueError("sanitization report counts are inconsistent")
        return self
