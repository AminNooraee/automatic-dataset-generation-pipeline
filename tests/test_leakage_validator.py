"""Comprehensive unit, integration, and security tests for Phase 3F leakage validation."""

from __future__ import annotations

import time
import traceback
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security import (
    LeakageValidationConfig,
    LeakageValidationError,
    LeakageValidationOutcome,
    LeakageValidationReport,
    LeakageValidationResult,
    LeakageValidator,
    SanitizationOrchestrator,
    SanitizationOrchestratorConfig,
    SanitizationReport,
    SanitizationResult,
    SanitizationTransformConfig,
    SanitizedSample,
    SanitizedValue,
    ValidatedSample,
)

_INT_ZERO = 0
_INT_ONE = 1
_INT_TWO = 2
_INT_THREE = 3
_INT_FOUR = 4
_INT_TEN = 10
_INT_FIFTEEN = 15
_INT_TWENTY = 20
_INT_THIRTY = 30
_INT_NINETY_NINE = 99
_INT_ONE_HUNDRED_ONE = 101
_FLOAT_FIVE = 5.0

_VALID_PSEUDONYM = "psn_v1_" + "a" * 43
_REDACTED_MARKER = "[REDACTED]"
_MASKED_MARKER = "[MASKED]"

_PEM_LABEL = "PRIVATE" + " KEY"
_SYNTHETIC_BEARER = "Bearer abcdef1234567890"  # pragma: allowlist secret
_SYNTHETIC_BASIC = "Basic c3ludGhldGljOnZhbHVl"  # pragma: allowlist secret
_SYNTHETIC_KEY = f"-----BEGIN {_PEM_LABEL}-----\nMIIEvgIBADANBg..."
_SYNTHETIC_JWT = (
    "eyJhbGciOiJub25l.eyJzdWIiOiJzeW50aGV0aWMifQ.syntheticSignature"  # pragma: allowlist secret
)
_SYNTHETIC_CONN = (
    "postgresql://synth_user:synth_secret@localhost:5432/db"  # pragma: allowlist secret
)
_SYNTHETIC_EMAIL = "alice@example.com"
_SYNTHETIC_PHONE = "+14155552671"
_SYNTHETIC_CARD = "4111-1111-1111-1111"
_SYNTHETIC_IBAN = "DE89370400440532013000"
_SYNTHETIC_SSN = "123-45-6789"


def _make_sample(
    columns: tuple[str, ...] = ("id", "name"),
    rows: tuple[tuple[SanitizedValue, ...], ...] = ((1, "Alice"),),
    *,
    schema_name: str = "public",
    table_name: str = "customers",
    policy_version: str = "1",
) -> SanitizedSample:
    return SanitizedSample(
        schema_name=schema_name,
        table_name=table_name,
        columns=columns,
        rows=rows,
        row_count=len(rows),
        truncated=False,
        policy_version=policy_version,
    )


def _make_report(
    total_fields: int = _INT_TWO,
    allowed_fields: int | None = None,
    *,
    dropped_fields: int = _INT_ZERO,
    policy_version: str = "1",
) -> SanitizationReport:
    actual_allowed = (total_fields - dropped_fields) if allowed_fields is None else allowed_fields
    return SanitizationReport(
        policy_version=policy_version,
        total_fields=total_fields,
        classified_fields=total_fields,
        redacted_fields=_INT_ZERO,
        masked_fields=_INT_ZERO,
        pseudonymized_fields=_INT_ZERO,
        dropped_fields=dropped_fields,
        allowed_fields=actual_allowed,
        unknown_fields=_INT_ZERO,
    )


def _make_result(
    sample: SanitizedSample | None = None,
    report: SanitizationReport | None = None,
) -> SanitizationResult:
    s = sample or _make_sample()
    r = report or _make_report(total_fields=len(s.columns), allowed_fields=len(s.columns))
    return SanitizationResult(sample=s, report=r)


# ==============================================================================
# Clean Samples & Normal Acceptance
# ==============================================================================


def test_clean_sample_is_accepted() -> None:
    validator = LeakageValidator()
    result = validator.validate(_make_result())

    assert result.accepted is True
    assert result.sample is not None
    assert isinstance(result.sample, ValidatedSample)
    assert result.report.outcome == LeakageValidationOutcome.ACCEPTED
    assert result.report.checked_fields == _INT_TWO
    assert result.report.checked_rows == _INT_ONE
    assert result.report.checked_cells == _INT_TWO
    assert result.report.reason_codes == ()
    assert dict(result.report.issue_counts) == {}


def test_validated_sample_properties_match_sanitized_sample() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id", "status", "active"),
        rows=((_INT_ONE_HUNDRED_ONE, "COMPLETE", True),),
        schema_name="app",
        table_name="events",
    )
    result = validator.validate(sample)

    assert result.accepted is True
    validated = result.sample
    assert validated is not None
    assert validated.schema_name == "app"
    assert validated.table_name == "events"
    assert validated.columns == ("id", "status", "active")
    assert validated.rows == ((_INT_ONE_HUNDRED_ONE, "COMPLETE", True),)
    assert validated.row_count == _INT_ONE
    assert validated.truncated is False
    assert validated.policy_version == "1"
    assert validated.validator_version == "leakage_validator.v1"
    assert validated.sample == sample


def test_validate_or_raise_returns_validated_sample_on_success() -> None:
    validator = LeakageValidator()
    sample = _make_sample()
    validated = validator.validate_or_raise(sample)

    assert isinstance(validated, ValidatedSample)
    assert validated.columns == ("id", "name")


def test_validate_accepts_sanitized_sample_directly() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("col1",), rows=(("clean text",),))
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None
    assert result.report.checked_fields == _INT_ONE


def test_empty_sample_zero_rows_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("a", "b"), rows=())
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None
    assert result.sample.row_count == _INT_ZERO
    assert result.report.checked_rows == _INT_ZERO
    assert result.report.checked_cells == _INT_ZERO


def test_empty_sample_zero_columns_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=(), rows=())
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None
    assert result.sample.columns == ()
    assert result.report.checked_fields == _INT_ZERO


# ==============================================================================
# Sanitization Marker Awareness
# ==============================================================================


def test_redacted_marker_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("secret_col",), rows=((_REDACTED_MARKER,),))
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None


def test_masked_marker_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("masked_col",), rows=((_MASKED_MARKER,),))
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None


def test_valid_pseudonym_token_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("pseudonym_col",), rows=((_VALID_PSEUDONYM,),))
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None


def test_genuine_null_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("nullable_col",), rows=((None,),))
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None


def test_mixed_markers_and_nulls_are_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id", "secret", "masked", "pseudo", "optional"),
        rows=((_INT_ONE, _REDACTED_MARKER, _MASKED_MARKER, _VALID_PSEUDONYM, None),),
    )
    result = validator.validate(sample)

    assert result.accepted is True
    assert result.sample is not None


# ==============================================================================
# Residual Sensitive Substring Detection
# ==============================================================================


def test_detects_residual_email_in_cell() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("notes",),
        rows=(("Please contact me at alice@example.com for info",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert result.sample is None
    assert "residual_email" in result.report.reason_codes
    assert result.report.issue_counts["residual_email"] == _INT_ONE


def test_detects_residual_international_phone() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("notes",),
        rows=(("Call our support desk at +1 (415) 555-2671 now",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert result.sample is None
    assert "residual_phone" in result.report.reason_codes


def test_arithmetic_plus_is_not_flagged_as_phone() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("math",),
        rows=(("Expression: 5 + 10 = 15",),),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_residual_payment_card_with_valid_luhn() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("memo",),
        rows=((f"Charged to card {_SYNTHETIC_CARD} successfully",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert result.sample is None
    assert "residual_payment_card" in result.report.reason_codes


def test_card_with_invalid_checksum_is_not_flagged_as_card() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("memo",),
        rows=(("Order ref 4111-1111-1111-1112 confirmed",),),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_residual_iban_with_valid_mod97() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("memo",),
        rows=((f"Wire transferred to {_SYNTHETIC_IBAN} today",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_iban" in result.report.reason_codes


def test_iban_with_invalid_checksum_is_not_flagged_as_iban() -> None:
    validator = LeakageValidator()
    invalid_iban = "DE89370400440532013001"  # pragma: allowlist secret
    sample = _make_sample(
        columns=("memo",),
        rows=((f"Reference code {invalid_iban} processed",),),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_residual_us_ssn() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("memo",),
        rows=((f"Applicant SSN is {_SYNTHETIC_SSN}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_national_id" in result.report.reason_codes


def test_detects_residual_bearer_auth_header() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("log",),
        rows=((f"HTTP Header: {_SYNTHETIC_BEARER}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_auth_header" in result.report.reason_codes


def test_detects_residual_basic_auth_header() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("log",),
        rows=((f"HTTP Header: {_SYNTHETIC_BASIC}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_auth_header" in result.report.reason_codes


def test_detects_residual_jwt() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("log",),
        rows=((f"Session token: {_SYNTHETIC_JWT}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_jwt" in result.report.reason_codes


def test_detects_residual_private_key_pem() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("key_dump",),
        rows=((f"Generated key:\n{_SYNTHETIC_KEY}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_private_key" in result.report.reason_codes


def test_detects_residual_connection_string_with_password() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("config",),
        rows=((f"DB_URI={_SYNTHETIC_CONN}",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_connection_string" in result.report.reason_codes


def test_connection_string_without_password_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("config",),
        rows=(("DB_URI=postgresql://synth_user@localhost:5432/db",),),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_credential_assignment() -> None:
    validator = LeakageValidator()
    payload = '{"password": "super_secret_password_123"}'  # pragma: allowlist secret
    sample = _make_sample(
        columns=("details",),
        rows=((payload,),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_credential_assignment" in result.report.reason_codes


def test_credential_assignment_with_redacted_value_is_accepted() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("details",),
        rows=(('{"user": "alice", "password": "[REDACTED]"}',),),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_secret_assignment() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("details",),
        rows=(("secret_key = super_secret_signing_key_456",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_secret_assignment" in result.report.reason_codes


# ==============================================================================
# Metadata Residual Leakage Inspection
# ==============================================================================


def test_ordinary_column_names_are_not_flagged() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id", "email", "password", "api_key", "phone_number", "ssn"),
        rows=(
            (
                _INT_ONE,
                _REDACTED_MARKER,
                _REDACTED_MARKER,
                _REDACTED_MARKER,
                _REDACTED_MARKER,
                _REDACTED_MARKER,
            ),
        ),
    )
    result = validator.validate(sample)

    assert result.accepted is True


def test_detects_embedded_secret_in_column_name() -> None:
    validator = LeakageValidator()
    bad_col = f"token_{_SYNTHETIC_BEARER.replace(' ', '_')}"
    sample = _make_sample(
        columns=("id", bad_col),
        rows=((_INT_ONE, "val"),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_auth_header" in result.report.reason_codes


def test_detects_embedded_email_in_table_name() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id",),
        rows=((_INT_ONE,),),
        table_name="users_alice@example.com_dump",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_email" in result.report.reason_codes


def test_detects_connection_string_in_schema_name() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id",),
        rows=((_INT_ONE,),),
        schema_name=_SYNTHETIC_CONN,
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "residual_connection_string" in result.report.reason_codes


# ==============================================================================
# Structural & Boundary Validation
# ==============================================================================


def test_rejects_unsupported_scalar_types() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id", "data"),
        rows=((_INT_ONE, b"raw_binary_bytes"),),  # type: ignore[arg-type]
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "unsupported_scalar_type" in result.report.reason_codes


def test_rejects_non_finite_float_nan() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id", "val"),
        rows=((_INT_ONE, float("nan")),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "non_finite_float" in result.report.reason_codes


def test_rejects_non_finite_float_infinity() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id", "val"),
        rows=((_INT_ONE, float("inf")),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "non_finite_float" in result.report.reason_codes


def test_rejects_nul_byte_in_cell() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("text",),
        rows=(("hello\x00world",),),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "nul_byte_in_cell" in result.report.reason_codes


def test_rejects_row_width_mismatch() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id", "name"),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "row_width_mismatch" in result.report.reason_codes


def test_rejects_row_count_mismatch() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id",),
        rows=((_INT_ONE,), (_INT_TWO,)),
        row_count=_INT_NINETY_NINE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "row_count_mismatch" in result.report.reason_codes


def test_rejects_duplicate_column_names() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id", "id"),
        rows=((_INT_ONE, _INT_TWO),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "duplicate_columns" in result.report.reason_codes


def test_rejects_malformed_truncated_flag() -> None:
    validator = LeakageValidator()
    sample = SanitizedSample.model_construct(
        schema_name="public",
        table_name="events",
        columns=("id",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated="not_a_bool",  # type: ignore[arg-type]
        policy_version="1",
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "malformed_truncated_flag" in result.report.reason_codes


# ==============================================================================
# Resource Limits & Budget Violations
# ==============================================================================


def test_rejects_max_fields_exceeded() -> None:
    config = LeakageValidationConfig(max_fields=_INT_TWO)
    validator = LeakageValidator(config)
    sample = _make_sample(columns=("a", "b", "c"), rows=((_INT_ONE, _INT_TWO, _INT_THREE),))
    result = validator.validate(sample)

    assert result.accepted is False
    assert "max_fields_exceeded" in result.report.reason_codes


def test_rejects_max_rows_exceeded() -> None:
    config = LeakageValidationConfig(max_rows=_INT_TWO)
    validator = LeakageValidator(config)
    sample = _make_sample(columns=("a",), rows=((_INT_ONE,), (_INT_TWO,), (_INT_THREE,)))
    result = validator.validate(sample)

    assert result.accepted is False
    assert "max_rows_exceeded" in result.report.reason_codes


def test_rejects_max_cells_exceeded() -> None:
    config = LeakageValidationConfig(max_cells=_INT_FOUR)
    validator = LeakageValidator(config)
    sample = _make_sample(
        columns=("a", "b", "c"),
        rows=((_INT_ONE, _INT_TWO, _INT_THREE), (_INT_FOUR, 5, 6)),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "max_cells_exceeded" in result.report.reason_codes


def test_rejects_max_text_chars_exceeded() -> None:
    config = LeakageValidationConfig(max_text_chars=_INT_TEN)
    validator = LeakageValidator(config)
    sample = _make_sample(columns=("text",), rows=(("a" * _INT_FIFTEEN,),))
    result = validator.validate(sample)

    assert result.accepted is False
    assert "max_text_chars_exceeded" in result.report.reason_codes


def test_rejects_max_total_text_chars_budget_exceeded() -> None:
    config = LeakageValidationConfig(
        max_text_chars=_INT_TWENTY,
        max_total_text_chars=_INT_THIRTY,
    )
    validator = LeakageValidator(config)
    sample = _make_sample(
        columns=("text",),
        rows=(("a" * _INT_FIFTEEN,), ("b" * _INT_FIFTEEN,), ("c" * _INT_FIFTEEN,)),
    )
    result = validator.validate(sample)

    assert result.accepted is False
    assert "max_total_text_chars_exceeded" in result.report.reason_codes


# ==============================================================================
# Audit Report Consistency
# ==============================================================================


def test_rejects_report_policy_version_mismatch() -> None:
    validator = LeakageValidator()
    sample = _make_sample(policy_version="1")
    report = _make_report(policy_version="2")
    result = validator.validate(sample, report=report)

    assert result.accepted is False
    assert "report_policy_version_mismatch" in result.report.reason_codes


def test_rejects_report_field_count_mismatch() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("id", "name"))
    report = _make_report(total_fields=_INT_THREE, dropped_fields=_INT_ZERO)
    result = validator.validate(sample, report=report)

    assert result.accepted is False
    assert "report_field_count_mismatch" in result.report.reason_codes


def test_rejects_malformed_report_type() -> None:
    validator = LeakageValidator()
    sample = _make_sample()
    result = validator.validate(sample, report="not_a_report")  # type: ignore[arg-type]

    assert result.accepted is False
    assert "malformed_report" in result.report.reason_codes


# ==============================================================================
# Security, Anti-Bypass, and Exception Detachment
# ==============================================================================


def test_validated_sample_cannot_be_directly_instantiated() -> None:
    sample = _make_sample()
    with pytest.raises(LeakageValidationError) as exc_info:
        ValidatedSample(sample, "v1")

    assert "ValidatedSample cannot be constructed directly" in str(exc_info.value)


def test_validated_sample_is_immutable() -> None:
    validator = LeakageValidator()
    result = validator.validate(_make_sample())
    validated = result.sample
    assert validated is not None

    with pytest.raises(TypeError, match="ValidatedSample is immutable"):
        validated.schema_name = "hack"  # type: ignore[misc]

    with pytest.raises(TypeError, match="ValidatedSample is immutable"):
        del validated.schema_name


def test_sanitized_sample_is_not_instance_of_validated_sample() -> None:
    sample = _make_sample()
    assert not isinstance(sample, ValidatedSample)


def test_invalid_target_type_raises_leakage_validation_error() -> None:
    validator = LeakageValidator()
    with pytest.raises(LeakageValidationError) as exc_info:
        validator.validate("completely_invalid_target")  # type: ignore[arg-type]

    assert "Validation target must be SanitizationResult or SanitizedSample" in str(exc_info.value)


def test_raise_on_rejection_config_raises_exception() -> None:
    config = LeakageValidationConfig(raise_on_rejection=True)
    validator = LeakageValidator(config)
    sample = _make_sample(columns=("memo",), rows=((f"Card {_SYNTHETIC_CARD}",),))

    with pytest.raises(LeakageValidationError):
        validator.validate(sample)


def test_validate_or_raise_raises_on_rejection() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("memo",), rows=((f"Card {_SYNTHETIC_CARD}",),))

    with pytest.raises(LeakageValidationError, match="Sanitized sample failed leakage validation"):
        validator.validate_or_raise(sample)


def test_injected_exception_context_is_completely_detached() -> None:
    """Injected secret in internal method does not leak in __context__ or traceback."""
    injected_secret = (
        "INJECTED_SECRET_LEAKAGE_FAILURE_XYZ"  # pragma: allowlist secret  # noqa: S105
    )
    validator = LeakageValidator()
    sample = _make_sample()

    with patch.object(
        validator,
        "_execute_validation",
        side_effect=RuntimeError(f"internal crash with: {injected_secret}"),
    ):
        with pytest.raises(LeakageValidationError) as exc_info:
            validator.validate(sample)

        err = exc_info.value
        assert err.__context__ is None
        assert err.__cause__ is None
        assert injected_secret not in str(err)
        assert injected_secret not in repr(err)

        formatted_tb = "".join(traceback.format_exception(err))
        assert injected_secret not in formatted_tb
        assert "RuntimeError" not in formatted_tb


def test_diagnostic_report_never_contains_raw_values_or_secrets() -> None:
    validator = LeakageValidator()
    secret_str = f"Bearer {_SYNTHETIC_BEARER}"
    sample = _make_sample(columns=("leak",), rows=((secret_str,),))
    result = validator.validate(sample)

    assert result.accepted is False
    report_dump = result.report.model_dump()
    report_repr = repr(result.report)

    assert _SYNTHETIC_BEARER not in report_repr
    assert _SYNTHETIC_BEARER not in str(report_dump)


def test_validated_sample_repr_does_not_print_rows() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("col1",), rows=(("sensitive_looking_allowlisted_val",),))
    result = validator.validate(sample)

    assert result.accepted is True
    validated = result.sample
    assert validated is not None
    assert "sensitive_looking_allowlisted_val" not in repr(validated)


def test_validated_sample_model_dump_contains_payload() -> None:
    validator = LeakageValidator()
    sample = _make_sample(columns=("col1",), rows=(("allowed_value",),))
    result = validator.validate(sample)

    assert result.accepted is True
    validated = result.sample
    assert validated is not None
    dump = validated.model_dump()
    assert dump["rows"] == (("allowed_value",),)


def test_validated_sample_equality_and_hash() -> None:
    validator = LeakageValidator()
    sample1 = _make_sample(columns=("id",), rows=((_INT_ONE,),))
    sample2 = _make_sample(columns=("id",), rows=((_INT_ONE,),))
    sample3 = _make_sample(columns=("id",), rows=((_INT_TWO,),))

    res1 = validator.validate(sample1).sample
    res2 = validator.validate(sample2).sample
    res3 = validator.validate(sample3).sample

    assert res1 == res2
    assert res1 != res3
    assert res1 != "other_type"
    assert hash(res1) == hash(res2)


# ==============================================================================
# End-to-End Integration: Phase 3E -> Phase 3F
# ==============================================================================


def test_phase3e_to_phase3f_clean_pipeline() -> None:
    """Clean synthetic raw sample passes Phase 3E and is accepted by Phase 3F."""
    raw_sample = SampleResult(
        schema_name="public",
        table_name="events",
        columns=("id", "status"),
        rows=((_INT_ONE, "ACTIVE"), (_INT_TWO, "PENDING")),
        row_count=_INT_TWO,
        truncated=False,
    )
    orch_config = SanitizationOrchestratorConfig(
        non_sensitive_allowlist=frozenset({"id", "status"}),
    )
    sanitizer = SanitizationOrchestrator(orch_config)
    sanitized_res = sanitizer.sanitize(raw_sample)

    validator = LeakageValidator()
    validation_res = validator.validate(sanitized_res)

    assert validation_res.accepted is True
    assert validation_res.sample is not None
    assert validation_res.sample.rows == ((_INT_ONE, "ACTIVE"), (_INT_TWO, "PENDING"))
    assert validation_res.report.outcome == LeakageValidationOutcome.ACCEPTED


def test_phase3e_to_phase3f_catches_residual_leakage_in_allowlisted_field() -> None:
    """Residual email in allowlisted free-text field is caught and rejected by Phase 3F."""
    raw_sample = SampleResult(
        schema_name="public",
        table_name="logs",
        columns=("id", "message"),
        rows=((_INT_ONE, f"User contacted support via {_SYNTHETIC_EMAIL} yesterday"),),
        row_count=_INT_ONE,
        truncated=False,
    )
    orch_config = SanitizationOrchestratorConfig(
        non_sensitive_allowlist=frozenset({"id", "message"}),
    )
    sanitizer = SanitizationOrchestrator(orch_config)
    sanitized_res = sanitizer.sanitize(raw_sample)

    assert sanitized_res.sample.columns == ("id", "message")
    assert _SYNTHETIC_EMAIL in str(sanitized_res.sample.rows)

    validator = LeakageValidator()
    validation_res = validator.validate(sanitized_res)

    assert validation_res.accepted is False
    assert validation_res.sample is None
    assert "residual_email" in validation_res.report.reason_codes


def test_phase3e_to_phase3f_pseudonymized_and_redacted_are_accepted() -> None:
    """Pseudonymized PII and redacted secrets pass Phase 3E and are accepted by Phase 3F."""
    key = "k" * 64
    raw_sample = SampleResult(
        schema_name="public",
        table_name="users",
        columns=("email", "password"),
        rows=(("alice@example.com", "my_secret_pass_123"),),
        row_count=_INT_ONE,
        truncated=False,
    )
    orch_config = SanitizationOrchestratorConfig(
        transform_config=SanitizationTransformConfig(pseudonymization_key=SecretStr(key)),
    )
    sanitizer = SanitizationOrchestrator(orch_config)
    sanitized_res = sanitizer.sanitize(raw_sample)

    first_cell = sanitized_res.sample.rows[_INT_ZERO][_INT_ZERO]
    assert isinstance(first_cell, str)
    assert first_cell.startswith("psn_v1_")
    assert sanitized_res.sample.rows[_INT_ZERO][_INT_ONE] == _REDACTED_MARKER

    validator = LeakageValidator()
    validation_res = validator.validate(sanitized_res)

    assert validation_res.accepted is True
    assert validation_res.sample is not None


# ==============================================================================
# Determinism and Non-Mutation
# ==============================================================================


def test_validation_is_deterministic_and_non_mutating() -> None:
    validator = LeakageValidator()
    sample = _make_sample(
        columns=("id", "label"),
        rows=((_INT_ONE, "alpha"), (_INT_TWO, "beta")),
    )
    original_rows = sample.rows

    res1 = validator.validate(sample)
    res2 = validator.validate(sample)

    assert res1.accepted == res2.accepted
    assert res1.report.model_dump() == res2.report.model_dump()
    assert sample.rows == original_rows


# ==============================================================================
# Codex Review Regression Tests (Findings 1 - 7)
# ==============================================================================


def test_finding_1_validated_sample_snapshot_isolation_and_threat_model() -> None:
    """Finding 1 (HIGH): ValidatedSample snapshots data and defends against accidental mutation.

    Verifies snapshotting isolates ValidatedSample from external caller mutations,
    to_sanitized_sample creates an equivalent SanitizedSample, and direct instantiation
    without private token is rejected.
    """
    initial_rows = ((_INT_ONE, "Alice"), (_INT_TWO, "Bob"))
    sample = _make_sample(columns=("id", "name"), rows=initial_rows)

    validator = LeakageValidator()
    result = validator.validate(sample)
    assert result.accepted is True
    assert result.sample is not None

    validated = result.sample

    # Test snapshot: mutating or creating new data does not affect validated sample
    exported = validated.to_sanitized_sample()
    assert isinstance(exported, SanitizedSample)
    assert exported.columns == validated.columns
    assert exported.rows == validated.rows
    assert exported.row_count == validated.row_count

    # Test immutability via __setattr__
    with pytest.raises(TypeError, match="ValidatedSample is immutable"):
        validated.rows = ((_INT_THREE, "Mallory"),)  # type: ignore[misc]

    # Test direct construction without private token is rejected with LeakageValidationError
    with pytest.raises(LeakageValidationError):
        ValidatedSample(sample, "1.0")

    with pytest.raises(LeakageValidationError):
        ValidatedSample(sample, "1.0", _token=object())

    # Verify object.__new__ creates uninitialized object, but pipeline refuses anything
    # not produced through validate()
    forged = object.__new__(ValidatedSample)
    assert isinstance(forged, ValidatedSample)
    assert not hasattr(forged, "_rows")


def test_finding_2_linear_uri_parsing_performance() -> None:
    """Finding 2 (HIGH): Linear O(N) URI scanning completes in milliseconds on pathological inputs.

    Replaces quadratic backtracking regex with candidate scanner that finishes 60,000 chars
    of non-URI delimiter patterns in milliseconds without hanging.
    """
    pathological_pattern = ":::::///::::@@@@" * 3750  # 60,000 characters
    sample = _make_sample(
        columns=("id", "blob"),
        rows=((_INT_ONE, pathological_pattern),),
    )

    config = LeakageValidationConfig(max_text_chars=100000, max_total_text_chars=100000)
    validator = LeakageValidator(config)
    start = time.perf_counter()
    result = validator.validate(sample)
    elapsed = time.perf_counter() - start

    assert result.accepted is True
    # Linear scan over 60KB typically completes in <0.05s. A generous threshold
    # prevents flaky CI timeouts under CPU throttling while reliably detecting quadratic blowup.
    msg = f"Pathological URI scanning took {elapsed:.2f}s, expected < {_FLOAT_FIVE}s"
    assert elapsed < _FLOAT_FIVE, msg


def test_finding_3_resource_budget_bypass_aborts_without_scanning_cells() -> None:
    """Finding 3 (HIGH): Dimension checks enforce limits upfront before any cell scanning.

    Oversized sample aborts immediately in _validate_structure without scanning cells.
    """
    num_cols = 100
    num_rows = 500
    cols = tuple(f"col_{i}" for i in range(num_cols))
    row = tuple("ok_value" for _ in range(num_cols))
    rows = tuple(row for _ in range(num_rows))  # 50,000 cells

    sample = _make_sample(columns=cols, rows=rows)

    # Config with max_rows=10 should abort on max_rows_exceeded before any cell scanning
    config = LeakageValidationConfig(max_rows=10)
    validator = LeakageValidator(config)

    with patch.object(validator, "_scan_string_cell") as mock_scan:
        result = validator.validate(sample)
        assert result.accepted is False
        assert "max_rows_exceeded" in result.report.reason_codes
        assert mock_scan.call_count == 0

    # Zero-row sample exceeding max_fields also aborts upfront
    cols_large = tuple(f"c_{i}" for i in range(20))
    zero_row_sample = _make_sample(columns=cols_large, rows=())
    config_fields = LeakageValidationConfig(max_fields=5)
    validator_fields = LeakageValidator(config_fields)
    res_fields = validator_fields.validate(zero_row_sample)
    assert res_fields.accepted is False
    assert "max_fields_exceeded" in res_fields.report.reason_codes


def test_finding_4_unchecked_config_validation() -> None:
    """Finding 4 (MEDIUM): LeakageValidator strictly validates config rejecting malformed models."""
    # Non-config instance raises TypeError
    with pytest.raises(TypeError, match="config must be an instance of LeakageValidationConfig"):
        LeakageValidator(config="not_a_config")  # type: ignore[arg-type]

    # Forged bounds via model_construct or model_copy
    with pytest.raises(ValueError, match="max_fields must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_fields=-1))

    with pytest.raises(ValueError, match="max_fields must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_fields=100000))

    with pytest.raises(ValueError, match="max_rows must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_rows=0))

    with pytest.raises(ValueError, match="max_rows must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_rows=2000000))

    with pytest.raises(ValueError, match="max_cells must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_cells=-5))

    with pytest.raises(ValueError, match="max_text_chars must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_text_chars=0))

    with pytest.raises(ValueError, match="max_total_text_chars must be an int"):
        LeakageValidator(LeakageValidationConfig.model_construct(max_total_text_chars=-1))

    with pytest.raises(ValueError, match="raise_on_rejection must be a bool"):
        LeakageValidator(
            LeakageValidationConfig.model_construct(raise_on_rejection="invalid")  # type: ignore[arg-type]
        )

    # model_copy update bypass
    valid_cfg = LeakageValidationConfig()
    corrupted_cfg = valid_cfg.model_copy(update={"max_rows": -99})
    with pytest.raises(ValueError, match="max_rows must be an int"):
        LeakageValidator(corrupted_cfg)


def test_finding_5_fabricated_report_revalidation() -> None:
    """Finding 5 (MEDIUM): Strict revalidation of SanitizationReport consistency."""
    validator = LeakageValidator()
    sample = _make_sample(columns=("col1", "col2"), rows=((_INT_ONE, "val"),))

    # Total fields negative
    bad_report1 = SanitizationReport.model_construct(
        policy_version="1",
        total_fields=-1,
        classified_fields=-1,
        redacted_fields=0,
        masked_fields=0,
        pseudonymized_fields=0,
        dropped_fields=0,
        allowed_fields=0,
        unknown_fields=0,
    )
    res1 = validator.validate(sample, report=bad_report1)
    assert res1.accepted is False
    assert "inconsistent_report_counts" in res1.report.reason_codes

    # Classified fields != total fields
    bad_report2 = SanitizationReport.model_construct(
        policy_version="1",
        total_fields=2,
        classified_fields=1,
        redacted_fields=0,
        masked_fields=0,
        pseudonymized_fields=0,
        dropped_fields=0,
        allowed_fields=1,
        unknown_fields=0,
    )
    res2 = validator.validate(sample, report=bad_report2)
    assert res2.accepted is False
    assert "inconsistent_report_counts" in res2.report.reason_codes

    # Actions sum != classified fields
    bad_report3 = SanitizationReport.model_construct(
        policy_version="1",
        total_fields=2,
        classified_fields=2,
        redacted_fields=1,
        masked_fields=0,
        pseudonymized_fields=0,
        dropped_fields=0,
        allowed_fields=0,  # 1 + 0 != 2
        unknown_fields=0,
    )
    res3 = validator.validate(sample, report=bad_report3)
    assert res3.accepted is False
    assert "inconsistent_report_counts" in res3.report.reason_codes

    # Unknown fields > classified fields
    bad_report4 = SanitizationReport.model_construct(
        policy_version="1",
        total_fields=2,
        classified_fields=2,
        redacted_fields=0,
        masked_fields=0,
        pseudonymized_fields=0,
        dropped_fields=0,
        allowed_fields=2,
        unknown_fields=5,  # > 2
    )
    res4 = validator.validate(sample, report=bad_report4)
    assert res4.accepted is False
    assert "inconsistent_report_counts" in res4.report.reason_codes

    # Dropped fields > total fields
    bad_report5 = SanitizationReport.model_construct(
        policy_version="1",
        total_fields=2,
        classified_fields=2,
        redacted_fields=0,
        masked_fields=0,
        pseudonymized_fields=0,
        dropped_fields=5,
        allowed_fields=0,
        unknown_fields=0,
    )
    res5 = validator.validate(sample, report=bad_report5)
    assert res5.accepted is False
    assert "inconsistent_report_counts" in res5.report.reason_codes


def test_finding_6_multi_uri_inspection_catches_unredacted_after_redacted() -> None:
    """Finding 6 (MEDIUM): All URI candidates are inspected in cell text."""
    validator = LeakageValidator()

    # Redacted URI followed by unredacted sensitive URI
    second_uri = "mysql://admin:real_secret_pwd@backup.internal:3306/db"  # pragma: allowlist secret
    mixed_uris = f"Logs: postgresql://user:[REDACTED]@db.internal:5432/app and mirror: {second_uri}"
    sample = _make_sample(
        columns=("id", "connection"),
        rows=((_INT_ONE, mixed_uris),),
    )
    res = validator.validate(sample)
    assert res.accepted is False
    assert "residual_connection_string" in res.report.reason_codes

    # Single redacted URI is accepted
    sample_redacted = _make_sample(
        columns=("id", "connection"),
        rows=((_INT_ONE, "postgresql://user:[REDACTED]@db.internal:5432/app"),),
    )
    assert validator.validate(sample_redacted).accepted is True

    # Single masked URI is accepted
    sample_masked = _make_sample(
        columns=("id", "connection"),
        rows=((_INT_ONE, "postgresql://user:[MASKED]@db.internal:5432/app"),),
    )
    assert validator.validate(sample_masked).accepted is True

    # URI without password is accepted
    sample_no_pw = _make_sample(
        columns=("id", "connection"),
        rows=((_INT_ONE, "postgresql://synth_user@localhost:5432/app"),),
    )
    assert validator.validate(sample_no_pw).accepted is True


def test_finding_7_canonicalization_and_metadata_checks() -> None:
    """Finding 7 (MEDIUM): Canonicalization and metadata scanning catches evasion."""
    validator = LeakageValidator()

    # Percent-encoded email in cell
    sample_encoded_email = _make_sample(
        columns=("id", "contact"),
        rows=((_INT_ONE, "Contact us at alice%40example.com today"),),
    )
    res_email = validator.validate(sample_encoded_email)
    assert res_email.accepted is False
    assert "residual_email" in res_email.report.reason_codes

    # Zero-width Unicode obfuscated email in cell
    sample_zw_email = _make_sample(
        columns=("id", "contact"),
        rows=((_INT_ONE, "alice\u200b@example.com"),),
    )
    res_zw = validator.validate(sample_zw_email)
    assert res_zw.accepted is False
    assert "residual_email" in res_zw.report.reason_codes

    # Zero-width space obfuscated credential assignment
    sample_zw_secret = _make_sample(
        columns=("id", "config"),
        rows=((_INT_ONE, "pass\u200bword=my_super_secret"),),  # pragma: allowlist secret
    )
    res_zw_sec = validator.validate(sample_zw_secret)
    assert res_zw_sec.accepted is False
    assert "residual_credential_assignment" in res_zw_sec.report.reason_codes

    # Zero-width space obfuscated secret assignment
    sample_zw_key = _make_sample(
        columns=("id", "config"),
        rows=((_INT_ONE, "secret_\u200bkey=my_super_secret"),),  # pragma: allowlist secret
    )
    res_zw_key = validator.validate(sample_zw_key)
    assert res_zw_key.accepted is False
    assert "residual_secret_assignment" in res_zw_key.report.reason_codes

    # Percent-encoded password in URI
    sample_encoded_conn = _make_sample(
        columns=("id", "uri"),
        rows=(
            (_INT_ONE, "postgresql://user:p%40ssword123@localhost/db"),  # pragma: allowlist secret
        ),
    )
    res_conn = validator.validate(sample_encoded_conn)
    assert res_conn.accepted is False
    assert "residual_connection_string" in res_conn.report.reason_codes

    # Sensitive credential assignment in schema_name
    sample_bad_schema = _make_sample(
        schema_name="password=my_secret_token",  # pragma: allowlist secret
        columns=("id", "val"),
        rows=((_INT_ONE, "test"),),
    )
    res_schema = validator.validate(sample_bad_schema)
    assert res_schema.accepted is False
    assert "residual_credential_assignment" in res_schema.report.reason_codes

    # Sensitive JWT in table_name
    sample_bad_table = _make_sample(
        table_name=_SYNTHETIC_JWT,
        columns=("id", "val"),
        rows=((_INT_ONE, "test"),),
    )
    res_table = validator.validate(sample_bad_table)
    assert res_table.accepted is False
    assert "residual_jwt" in res_table.report.reason_codes

    # Valid ordinary identifiers produce no false positives
    sample_legit = _make_sample(
        schema_name="app_schema",
        table_name="customer_accounts",
        columns=("id", "email", "password_hash", "status"),
        rows=((_INT_ONE, "[REDACTED]", "[REDACTED]", "ACTIVE"),),
    )
    res_legit = validator.validate(sample_legit)
    assert res_legit.accepted is True
    assert res_legit.report.outcome == LeakageValidationOutcome.ACCEPTED


def test_leakage_validator_uncovered_edge_cases() -> None:
    """Exercise remaining edge cases and defensive checks in leakage validator."""
    validator = LeakageValidator()

    # Card with digits where val * 2 > 9 (exercises val -= 9 in Luhn)
    sample_card = _make_sample(
        columns=("id", "card"),
        rows=((_INT_ONE, "4532-0150-1234-5671"),),
    )
    res_card = validator.validate(sample_card)
    assert res_card.accepted is False
    assert "residual_payment_card" in res_card.report.reason_codes

    # Redacted Bearer auth header is accepted
    sample_redacted_bearer = _make_sample(
        columns=("id", "auth"),
        rows=((_INT_ONE, "Bearer [REDACTED]"),),
    )
    assert validator.validate(sample_redacted_bearer).accepted is True

    # Masked Bearer auth header is accepted
    sample_masked_bearer = _make_sample(
        columns=("id", "auth"),
        rows=((_INT_ONE, "Bearer [MASKED]"),),
    )
    assert validator.validate(sample_masked_bearer).accepted is True

    # Redacted secret assignment is accepted
    sample_redacted_secret = _make_sample(
        columns=("id", "secret"),
        rows=((_INT_ONE, "secret_key = [REDACTED]"),),
    )
    assert validator.validate(sample_redacted_secret).accepted is True

    # Unexpected internal exception triggers fail-closed error with detached context
    with patch.object(validator, "_execute_validation", side_effect=RuntimeError("unexpected")):
        with pytest.raises(LeakageValidationError) as exc_info:
            validator.validate(_make_sample())
        assert exc_info.value.__context__ is None
        assert exc_info.value.__cause__ is None


def test_leakage_validator_forged_constructs_and_model_validators() -> None:
    """Exercise forged model_construct objects and Pydantic model invariants."""
    validator = LeakageValidator()

    # Malformed policy_version (empty or NUL byte) via model_construct
    sample_bad_pol = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("id", "val"),
        rows=((_INT_ONE, "Alice"),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="",
    )
    assert validator.validate(sample_bad_pol).accepted is False

    sample_nul_pol = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("id", "val"),
        rows=((_INT_ONE, "Alice"),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1\x00",
    )
    assert validator.validate(sample_nul_pol).accepted is False

    # Malformed identifier in schema_name or table_name via model_construct
    sample_bad_schema = SanitizedSample.model_construct(
        schema_name="",
        table_name="customers",
        columns=("id", "val"),
        rows=((_INT_ONE, "Alice"),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    assert validator.validate(sample_bad_schema).accepted is False

    sample_nul_schema = SanitizedSample.model_construct(
        schema_name="public\x00",
        table_name="customers",
        columns=("id", "val"),
        rows=((_INT_ONE, "Alice"),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    assert validator.validate(sample_nul_schema).accepted is False

    # Malformed column names via model_construct
    sample_bad_col = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    assert validator.validate(sample_bad_col).accepted is False

    sample_nul_col = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("col\x00",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    assert validator.validate(sample_nul_col).accepted is False

    # Row width mismatch via model_construct
    sample_row_mismatch = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("id", "val"),
        rows=((_INT_ONE, "val", "extra"),),
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    res_width = validator.validate(sample_row_mismatch)
    assert res_width.accepted is False
    assert "row_width_mismatch" in res_width.report.reason_codes

    # Non-scalar cell type via model_construct
    sample_bad_scalar = SanitizedSample.model_construct(
        schema_name="public",
        table_name="customers",
        columns=("id", "data"),
        rows=((_INT_ONE, {"key": "value"}),),  # type: ignore[arg-type]
        row_count=_INT_ONE,
        truncated=False,
        policy_version="1",
    )
    res_scalar = validator.validate(sample_bad_scalar)
    assert res_scalar.accepted is False
    assert "unsupported_scalar_type" in res_scalar.report.reason_codes

    # LeakageValidationReport model validators
    with pytest.raises(ValueError, match="reason codes must be lowercase"):
        LeakageValidationReport(
            outcome=LeakageValidationOutcome.REJECTED,
            validator_version="1.0",
            policy_version="1",
            checked_fields=_INT_ONE,
            checked_rows=_INT_ONE,
            checked_cells=_INT_ONE,
            checked_text_chars=_INT_ONE,
            reason_codes=("INVALID_UPPERCASE",),
        )

    with pytest.raises(ValueError, match="accepted report cannot contain reason codes"):
        LeakageValidationReport(
            outcome=LeakageValidationOutcome.ACCEPTED,
            validator_version="1.0",
            policy_version="1",
            checked_fields=_INT_ONE,
            checked_rows=_INT_ONE,
            checked_cells=_INT_ONE,
            checked_text_chars=_INT_ONE,
            reason_codes=("some_code",),
        )

    with pytest.raises(ValueError, match="rejected report must specify at least one reason code"):
        LeakageValidationReport(
            outcome=LeakageValidationOutcome.REJECTED,
            validator_version="1.0",
            policy_version="1",
            checked_fields=_INT_ONE,
            checked_rows=_INT_ONE,
            checked_cells=_INT_ONE,
            checked_text_chars=_INT_ONE,
            reason_codes=(),
        )

    # LeakageValidationResult model validators
    rep_accepted = LeakageValidationReport(
        outcome=LeakageValidationOutcome.ACCEPTED,
        validator_version="1.0",
        policy_version="1",
        checked_fields=_INT_ONE,
        checked_rows=_INT_ONE,
        checked_cells=_INT_ONE,
        checked_text_chars=_INT_ONE,
    )
    with pytest.raises(ValueError, match="accepted result must contain ValidatedSample"):
        LeakageValidationResult(accepted=True, sample=None, report=rep_accepted)

    rep_rejected = LeakageValidationReport(
        outcome=LeakageValidationOutcome.REJECTED,
        validator_version="1.0",
        policy_version="1",
        checked_fields=_INT_ONE,
        checked_rows=_INT_ONE,
        checked_cells=_INT_ONE,
        checked_text_chars=_INT_ONE,
        reason_codes=("malformed_columns",),
    )
    valid_res = validator.validate(_make_sample())
    assert valid_res.sample is not None
    with pytest.raises(ValueError, match="rejected result must have sample=None"):
        LeakageValidationResult(accepted=False, sample=valid_res.sample, report=rep_rejected)
