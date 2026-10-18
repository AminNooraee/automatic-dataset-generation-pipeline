"""Comprehensive unit and integration tests for Phase 3E sanitization orchestration."""

from __future__ import annotations

import itertools
import traceback
from datetime import UTC, date, datetime, time
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest
from pydantic import SecretStr, ValidationError

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security import (
    FieldClassification,
    FieldReference,
    PIIDetectionConfig,
    PIIDetectionResult,
    SanitizationAction,
    SanitizationOrchestrator,
    SanitizationOrchestratorConfig,
    SanitizationOrchestratorError,
    SanitizationPolicy,
    SanitizationReport,
    SanitizationResult,
    SanitizationTransformConfig,
    SanitizationTransformer,
    SanitizedSample,
    SecretCredentialDetector,
    SecretDetectionConfig,
    SecretDetectionResult,
    SensitivityClass,
)
from automatic_dataset_generation.security.sanitizer import (
    _ABSOLUTE_MAX_CELLS,
    _merge_classifications,
)

_LONG_KEY = "k" * 64
_ALT_KEY = "m" * 64
_REDACTED_MARKER = "[REDACTED]"
_MASKED_MARKER = "[MASKED]"
_PEM_KEY_LABEL = "PRIVATE" + " KEY"
_SYNTHETIC_BEARER = "Bearer abcdef1234567890"  # pragma: allowlist secret
_SYNTHETIC_KEY_A = f"-----BEGIN {_PEM_KEY_LABEL}-----\nMIIEvgIBADANBg..."
_SYNTHETIC_KEY_B = f"-----BEGIN {_PEM_KEY_LABEL}-----\nMIIEvgIBADANBg..."
_SYNTHETIC_KEY_SECRET = (
    "super_secret_pseudonymization_key_value_123"  # pragma: allowlist secret  # noqa: S105
)

_INT_ZERO = 0
_INT_ONE = 1
_INT_TWO = 2
_INT_THREE = 3
_INT_FOUR = 4
_INT_NUM = 42

_CONFIDENCE_LOW = 0.2
_CONFIDENCE_MID = 0.8
_CONFIDENCE_HIGH = 0.9
_CONFIDENCE_EXACT = 0.99


def _make_config(  # noqa: PLR0913
    *,
    key: str | None = _LONG_KEY,
    allowlist: frozenset[str] | None = None,
    policy: SanitizationPolicy | None = None,
    secret_config: SecretDetectionConfig | None = None,
    pii_config: PIIDetectionConfig | None = None,
    max_fields: int | None = None,
    max_rows: int | None = None,
    max_cells: int | None = None,
) -> SanitizationOrchestratorConfig:
    kwargs: dict[str, object] = {
        "transform_config": SanitizationTransformConfig(
            pseudonymization_key=SecretStr(key) if key else None
        )
    }
    if allowlist is not None:
        kwargs["non_sensitive_allowlist"] = allowlist
    if policy is not None:
        kwargs["policy"] = policy
    if secret_config is not None:
        kwargs["secret_config"] = secret_config
    if pii_config is not None:
        kwargs["pii_config"] = pii_config
    if max_fields is not None:
        kwargs["max_fields"] = max_fields
    if max_rows is not None:
        kwargs["max_rows"] = max_rows
    if max_cells is not None:
        kwargs["max_cells"] = max_cells
    return SanitizationOrchestratorConfig(**kwargs)  # type: ignore[arg-type]


def _make_sample(
    *,
    columns: tuple[str, ...],
    rows: tuple[tuple[object, ...], ...],
    schema: str = "public",
    table: str = "users",
    truncated: bool = False,
) -> SampleResult:
    return SampleResult(
        schema_name=schema,
        table_name=table,
        columns=columns,
        rows=rows,
        row_count=len(rows),
        truncated=truncated,
    )


# ==============================================================================
# Configuration and Validation Tests
# ==============================================================================


def test_config_defaults() -> None:
    config = SanitizationOrchestratorConfig()
    assert config.policy == SanitizationPolicy()
    assert config.transform_config == SanitizationTransformConfig()
    assert config.secret_config == SecretDetectionConfig()
    assert config.pii_config == PIIDetectionConfig()
    assert config.non_sensitive_allowlist == frozenset()


def test_config_is_frozen() -> None:
    config = SanitizationOrchestratorConfig()
    with pytest.raises(ValidationError, match="frozen"):
        config.policy = SanitizationPolicy()  # type: ignore[misc]


def test_config_validates_allowlist_elements() -> None:
    with pytest.raises(
        ValidationError,
        match="allowlist entries must be non-empty text without NUL",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=[""])

    with pytest.raises(
        ValidationError,
        match="allowlist entries must be non-empty text without NUL",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=["has\x00nul"])

    with pytest.raises(
        ValidationError,
        match="allowlist entries must be non-empty text without NUL",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=[_INT_NUM])

    valid = SanitizationOrchestratorConfig(non_sensitive_allowlist=["col_a", "col_b"])
    assert valid.non_sensitive_allowlist == frozenset({"col_a", "col_b"})

    none_allowlist = SanitizationOrchestratorConfig(non_sensitive_allowlist=None)
    assert none_allowlist.non_sensitive_allowlist == frozenset()

    gen_allowlist = SanitizationOrchestratorConfig(non_sensitive_allowlist=(c for c in ["x", "y"]))
    assert gen_allowlist.non_sensitive_allowlist == frozenset({"x", "y"})

    with pytest.raises(
        ValidationError,
        match="allowlist entries must be non-empty text without NUL",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=(c for c in [""]))

    with pytest.raises(
        ValidationError,
        match="non_sensitive_allowlist must be an iterable of non-empty strings",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=_INT_NUM)


def test_orchestrator_rejects_invalid_config_type() -> None:
    with pytest.raises(TypeError, match="config must be a SanitizationOrchestratorConfig"):
        SanitizationOrchestrator(config="invalid")  # type: ignore[arg-type]


def test_orchestrator_rejects_non_sample_result() -> None:
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(TypeError, match="sample must be a SampleResult"):
        orchestrator.sanitize({"columns": ("id",), "rows": ()})  # type: ignore[arg-type]


def test_orchestrator_rejects_malformed_sample_identifiers() -> None:
    orchestrator = SanitizationOrchestrator(_make_config())

    sample_empty_schema = SampleResult.model_construct(
        schema_name="",
        table_name="t",
        columns=("id",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample_empty_schema)

    sample_nul_table = SampleResult.model_construct(
        schema_name="s",
        table_name="t\x00bad",
        columns=("id",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample_nul_table)

    sample_empty_column = SampleResult.model_construct(
        schema_name="s",
        table_name="t",
        columns=("",),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample_empty_column)

    sample_duplicate_column = SampleResult.model_construct(
        schema_name="s",
        table_name="t",
        columns=("col", "col"),
        rows=((_INT_ONE, _INT_TWO),),
        row_count=_INT_ONE,
        truncated=False,
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample_duplicate_column)


# ==============================================================================
# End-to-End Orchestration: Detector Integration
# ==============================================================================


def test_end_to_end_secret_and_pii_sanitization() -> None:
    sample = _make_sample(
        columns=("id", "api_key", "email", "notes"),
        rows=(
            (_INT_ONE, _SYNTHETIC_BEARER, "user1@example.com", "customer note 1"),
            (_INT_TWO, _SYNTHETIC_BEARER, "user2@example.com", "customer note 2"),
        ),
    )
    config = _make_config(allowlist=frozenset({"id"}))
    orchestrator = SanitizationOrchestrator(config)

    result = orchestrator.sanitize(sample)
    assert isinstance(result, SanitizationResult)
    assert isinstance(result.sample, SanitizedSample)
    assert isinstance(result.report, SanitizationReport)

    assert result.sample.columns == ("id", "api_key", "email", "notes")
    assert result.sample.row_count == _INT_TWO
    assert not result.sample.truncated

    row0 = result.sample.rows[_INT_ZERO]
    assert row0[_INT_ZERO] == _INT_ONE
    assert row0[_INT_ONE] == _REDACTED_MARKER
    assert isinstance(row0[_INT_TWO], str)
    assert str(row0[_INT_TWO]).startswith("psn_v1_")
    assert row0[_INT_THREE] == _REDACTED_MARKER

    rep = result.report
    assert rep.total_fields == _INT_FOUR
    assert rep.classified_fields == _INT_FOUR
    assert rep.allowed_fields == _INT_ONE
    assert rep.redacted_fields == _INT_TWO
    assert rep.pseudonymized_fields == _INT_ONE
    assert rep.masked_fields == _INT_ZERO
    assert rep.dropped_fields == _INT_ZERO
    assert rep.unknown_fields == _INT_ONE


def test_unclassified_fields_default_to_unknown_fail_closed() -> None:
    sample = _make_sample(
        columns=("counter", "status_flag"),
        rows=((_INT_NUM, "active"), (_INT_NUM, "inactive")),
    )
    orchestrator = SanitizationOrchestrator(_make_config(allowlist=frozenset()))
    result = orchestrator.sanitize(sample)

    assert result.sample.rows == (
        (_REDACTED_MARKER, _REDACTED_MARKER),
        (_REDACTED_MARKER, _REDACTED_MARKER),
    )
    assert result.report.unknown_fields == _INT_TWO
    assert result.report.redacted_fields == _INT_TWO
    assert result.report.allowed_fields == _INT_ZERO


def test_allowlist_cannot_override_positive_detector_finding() -> None:
    sample = _make_sample(
        columns=("email", "auth_token"),
        rows=(("alice@example.com", _SYNTHETIC_BEARER),),
    )
    config = _make_config(allowlist=frozenset({"email", "auth_token"}))
    orchestrator = SanitizationOrchestrator(config)

    result = orchestrator.sanitize(sample)
    val0 = result.sample.rows[_INT_ZERO][_INT_ZERO]
    val1 = result.sample.rows[_INT_ZERO][_INT_ONE]
    assert isinstance(val0, str)
    assert val0.startswith("psn_v1_")
    assert val1 == _REDACTED_MARKER

    assert result.report.allowed_fields == _INT_ZERO
    assert result.report.pseudonymized_fields == _INT_ONE
    assert result.report.redacted_fields == _INT_ONE


def test_allowlist_normalizes_supported_scalar_types() -> None:
    now = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
    d = date(2026, 10, 18)
    t = time(12, 0, 0)
    uid = UUID("12345678-1234-5678-1234-567812345678")
    sample = _make_sample(
        columns=("num", "price", "dt", "day", "tm", "guid", "active"),
        rows=((_INT_NUM, Decimal("19.99"), now, d, t, uid, True),),
    )
    allowlist = frozenset({"num", "price", "dt", "day", "tm", "guid", "active"})
    orchestrator = SanitizationOrchestrator(_make_config(allowlist=allowlist))

    result = orchestrator.sanitize(sample)
    row = result.sample.rows[_INT_ZERO]
    assert row[_INT_ZERO] == _INT_NUM
    assert row[_INT_ONE] == "19.99"
    assert row[_INT_TWO] == now.isoformat()
    assert row[_INT_THREE] == d.isoformat()
    assert row[_INT_FOUR] == t.isoformat()
    assert row[5] == str(uid)
    assert row[6] is True


# ==============================================================================
# Conflicting Detector Classifications & Policy-Aware Precedence
# ==============================================================================


def test_merge_classifications_precedence_credential_over_pii() -> None:
    ref = FieldReference(schema_name="s", table_name="t", column_name="auth_email")
    secret_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.CREDENTIAL,
        confidence=_CONFIDENCE_HIGH,
        detector="secret.detector",
    )
    pii_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.PII,
        confidence=_CONFIDENCE_EXACT,
        detector="pii.detector",
    )

    sec_res = SecretDetectionResult(
        detector_version="secret_credential.v1",
        classifications=(secret_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )
    pii_res = PIIDetectionResult(
        detector_version="pii.v1",
        classifications=(pii_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )

    merged = _merge_classifications(sec_res, pii_res)
    assert merged["auth_email"].sensitivity == SensitivityClass.CREDENTIAL


def test_merge_classifications_precedence_unknown_over_pii_default_policy() -> None:
    ref = FieldReference(schema_name="s", table_name="t", column_name="data")
    secret_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.UNKNOWN,
        confidence=_CONFIDENCE_LOW,
        detector="secret.uninspectable",
    )
    pii_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.PII,
        confidence=_CONFIDENCE_HIGH,
        detector="pii.column_name",
    )

    sec_res = SecretDetectionResult(
        detector_version="secret_credential.v1",
        classifications=(secret_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )
    pii_res = PIIDetectionResult(
        detector_version="pii.v1",
        classifications=(pii_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )

    merged = _merge_classifications(sec_res, pii_res, policy=SanitizationPolicy())
    assert merged["data"].sensitivity == SensitivityClass.UNKNOWN


def test_merge_classifications_policy_aware_custom_policy() -> None:
    ref = FieldReference(schema_name="s", table_name="t", column_name="sensitive_col")
    sec_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.SECRET,
        confidence=_CONFIDENCE_EXACT,
        detector="secret.detector",
    )
    pii_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.PII,
        confidence=_CONFIDENCE_EXACT,
        detector="pii.detector",
    )

    sec_res = SecretDetectionResult(
        detector_version="secret_credential.v1",
        classifications=(sec_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )
    pii_res = PIIDetectionResult(
        detector_version="pii.v1",
        classifications=(pii_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )

    custom_policy = SanitizationPolicy(
        actions={
            SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
            SensitivityClass.PII: SanitizationAction.DROP,
            SensitivityClass.SECRET: SanitizationAction.REDACT,
            SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
            SensitivityClass.UNKNOWN: SanitizationAction.REDACT,
        }
    )

    merged = _merge_classifications(sec_res, pii_res, policy=custom_policy)
    assert merged["sensitive_col"].sensitivity == SensitivityClass.PII


def test_merge_classifications_confidence_tie_break() -> None:
    ref = FieldReference(schema_name="s", table_name="t", column_name="col")
    sec_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.UNKNOWN,
        confidence=_CONFIDENCE_LOW,
        detector="secret.det",
    )
    pii_clf = FieldClassification(
        field=ref,
        sensitivity=SensitivityClass.UNKNOWN,
        confidence=_CONFIDENCE_MID,
        detector="pii.det",
    )

    sec_res = SecretDetectionResult(
        detector_version="secret_credential.v1",
        classifications=(sec_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )
    pii_res = PIIDetectionResult(
        detector_version="pii.v1",
        classifications=(pii_clf,),
        scanned_fields=_INT_ONE,
        scanned_rows=_INT_ONE,
        scanned_cells=_INT_ONE,
    )

    merged = _merge_classifications(sec_res, pii_res)
    assert merged["col"].confidence == _CONFIDENCE_MID
    assert merged["col"].detector == "pii.det"


# ==============================================================================
# Nulls and Dropped Columns
# ==============================================================================


def test_genuine_nulls_are_preserved_not_confused_with_drop() -> None:
    sample = _make_sample(
        columns=("id", "email", "api_key", "unclassified"),
        rows=((None, None, None, None),),
    )
    config = _make_config(allowlist=frozenset({"id"}))
    orchestrator = SanitizationOrchestrator(config)

    result = orchestrator.sanitize(sample)
    assert result.sample.columns == ("id", "email", "api_key", "unclassified")
    assert result.sample.rows == ((None, None, None, None),)
    assert result.report.dropped_fields == _INT_ZERO


def test_column_dropping_omits_column_and_cells() -> None:
    sample = _make_sample(
        columns=("id", "secret_key", "email"),
        rows=(
            (_INT_ONE, _SYNTHETIC_KEY_A, "user@example.com"),
            (_INT_TWO, _SYNTHETIC_KEY_B, "user2@example.com"),
        ),
    )
    drop_policy = SanitizationPolicy(
        actions={
            SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
            SensitivityClass.PII: SanitizationAction.PSEUDONYMIZE,
            SensitivityClass.SECRET: SanitizationAction.DROP,
            SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
            SensitivityClass.UNKNOWN: SanitizationAction.REDACT,
        }
    )
    config = _make_config(allowlist=frozenset({"id"}), policy=drop_policy)
    orchestrator = SanitizationOrchestrator(config)

    result = orchestrator.sanitize(sample)
    assert result.sample.columns == ("id", "email")
    assert len(result.sample.rows[_INT_ZERO]) == _INT_TWO
    assert result.sample.rows[_INT_ZERO][_INT_ZERO] == _INT_ONE
    val = result.sample.rows[_INT_ZERO][_INT_ONE]
    assert isinstance(val, str)
    assert val.startswith("psn_v1_")

    assert result.report.dropped_fields == _INT_ONE
    assert result.report.allowed_fields == _INT_ONE
    assert result.report.pseudonymized_fields == _INT_ONE
    assert result.report.total_fields == _INT_THREE


def test_all_columns_dropped() -> None:
    sample = _make_sample(
        columns=("secret_a", "secret_b"),
        rows=(
            (_SYNTHETIC_KEY_A, _SYNTHETIC_KEY_B),
            (_SYNTHETIC_KEY_A, _SYNTHETIC_KEY_B),
        ),
    )
    drop_all_policy = SanitizationPolicy(
        actions={
            SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
            SensitivityClass.PII: SanitizationAction.DROP,
            SensitivityClass.SECRET: SanitizationAction.DROP,
            SensitivityClass.CREDENTIAL: SanitizationAction.DROP,
            SensitivityClass.UNKNOWN: SanitizationAction.DROP,
        }
    )
    orchestrator = SanitizationOrchestrator(_make_config(policy=drop_all_policy))
    result = orchestrator.sanitize(sample)

    assert result.sample.columns == ()
    assert result.sample.rows == ((), ())
    assert result.sample.row_count == _INT_TWO
    assert result.report.dropped_fields == _INT_TWO


# ==============================================================================
# Empty Samples
# ==============================================================================


def test_empty_sample_zero_rows() -> None:
    sample = _make_sample(
        columns=("id", "email"),
        rows=(),
    )
    orchestrator = SanitizationOrchestrator(_make_config(allowlist=frozenset({"id"})))
    result = orchestrator.sanitize(sample)

    assert result.sample.columns == ("id", "email")
    assert result.sample.rows == ()
    assert result.sample.row_count == _INT_ZERO
    assert result.report.total_fields == _INT_TWO
    assert result.report.classified_fields == _INT_TWO
    assert result.report.allowed_fields == _INT_ONE
    assert result.report.pseudonymized_fields == _INT_ONE


def test_empty_sample_zero_columns_zero_rows() -> None:
    sample = _make_sample(columns=(), rows=())
    orchestrator = SanitizationOrchestrator(_make_config())
    result = orchestrator.sanitize(sample)

    assert result.sample.columns == ()
    assert result.sample.rows == ()
    assert result.sample.row_count == _INT_ZERO
    assert result.report.total_fields == _INT_ZERO
    assert result.report.classified_fields == _INT_ZERO


# ==============================================================================
# Pseudonymization Determinism & Key Handling
# ==============================================================================


def test_pseudonymization_determinism() -> None:
    sample = _make_sample(
        columns=("email",),
        rows=(("alice@example.com",), ("bob@example.com",), ("alice@example.com",)),
    )
    orchestrator1 = SanitizationOrchestrator(_make_config(key=_LONG_KEY))
    orchestrator2 = SanitizationOrchestrator(_make_config(key=_ALT_KEY))

    res1 = orchestrator1.sanitize(sample)
    res2 = orchestrator2.sanitize(sample)

    token_alice_1 = res1.sample.rows[_INT_ZERO][_INT_ZERO]
    token_bob_1 = res1.sample.rows[_INT_ONE][_INT_ZERO]
    token_alice_duplicate = res1.sample.rows[_INT_TWO][_INT_ZERO]

    token_alice_2 = res2.sample.rows[_INT_ZERO][_INT_ZERO]

    assert token_alice_1 == token_alice_duplicate
    assert token_alice_1 != token_bob_1
    assert token_alice_1 != token_alice_2


def test_missing_pseudonymization_key_raises_error() -> None:
    sample = _make_sample(
        columns=("email",),
        rows=(("alice@example.com",),),
    )
    orchestrator = SanitizationOrchestrator(_make_config(key=None))
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_missing_pseudonymization_key_raises_error_even_with_zero_rows() -> None:
    sample = _make_sample(
        columns=("email",),
        rows=(),
    )
    orchestrator = SanitizationOrchestrator(_make_config(key=None))
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_missing_pseudonymization_key_raises_error_even_with_null_values() -> None:
    sample = _make_sample(
        columns=("email",),
        rows=((None,),),
    )
    orchestrator = SanitizationOrchestrator(_make_config(key=None))
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


# ==============================================================================
# Unsupported Objects, Oversized Inputs & Bounded Processing
# ==============================================================================


def test_unsupported_object_fails_closed() -> None:
    # 1. Non-finite float in an allowlisted column fails closed on ALLOW
    sample_nan = _make_sample(
        columns=("score",),
        rows=((float("nan"),),),
    )
    orchestrator_allow = SanitizationOrchestrator(_make_config(allowlist=frozenset({"score"})))
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator_allow.sanitize(sample_nan)

    # 2. Unsupported arbitrary driver object cannot be canonicalized under PSEUDONYMIZE
    class CustomDriverObject:
        def __str__(self) -> str:
            return "unsafe_driver_str"

    sample_custom = _make_sample(
        columns=("custom_col",),
        rows=((CustomDriverObject(),),),
    )
    pseudonymize_unknown_policy = SanitizationPolicy(
        actions={
            SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
            SensitivityClass.PII: SanitizationAction.PSEUDONYMIZE,
            SensitivityClass.SECRET: SanitizationAction.REDACT,
            SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
            SensitivityClass.UNKNOWN: SanitizationAction.PSEUDONYMIZE,
        }
    )
    orchestrator_psn = SanitizationOrchestrator(
        _make_config(policy=pseudonymize_unknown_policy, key=_LONG_KEY)
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator_psn.sanitize(sample_custom)


def test_exceeding_absolute_max_cells_raises_error() -> None:
    sample = SampleResult.model_construct(
        schema_name="s",
        table_name="t",
        columns=("a", "b"),
        rows=(),
        row_count=_ABSOLUTE_MAX_CELLS,
        truncated=True,
    )
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_exceeding_detector_max_cells_raises_error() -> None:
    secret_cfg = SecretDetectionConfig(max_cells=_INT_FOUR)
    orchestrator = SanitizationOrchestrator(_make_config(secret_config=secret_cfg))

    sample = _make_sample(
        columns=("c1", "c2", "c3"),
        rows=((_INT_ONE, _INT_TWO, _INT_THREE), (_INT_FOUR, 5, 6)),
    )
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


# ==============================================================================
# Injected Failures & Atomicity
# ==============================================================================


def test_injected_detector_failure_fails_atomically() -> None:
    sample = _make_sample(
        columns=("id", "email"),
        rows=((_INT_ONE, "alice@example.com"),),
    )
    orchestrator = SanitizationOrchestrator(_make_config())

    with patch.object(SecretCredentialDetector, "detect", side_effect=RuntimeError("injected")):
        with pytest.raises(SanitizationOrchestratorError) as exc_info:
            orchestrator.sanitize(sample)
        assert "injected" not in str(exc_info.value)


def test_injected_transformer_failure_fails_atomically() -> None:
    sample = _make_sample(
        columns=("id",),
        rows=((_INT_ONE,),),
    )
    orchestrator = SanitizationOrchestrator(_make_config(allowlist=frozenset({"id"})))

    with patch.object(SanitizationTransformer, "transform", side_effect=RuntimeError("injected")):
        with pytest.raises(SanitizationOrchestratorError) as exc_info:
            orchestrator.sanitize(sample)
        assert "injected" not in str(exc_info.value)


# ==============================================================================
# Immutability and Non-Disclosure
# ==============================================================================


def test_source_sample_remains_unmodified() -> None:
    source_rows = ((_INT_ONE, "alice@example.com"),)
    source_cols = ("id", "email")
    sample = _make_sample(columns=source_cols, rows=source_rows)

    orchestrator = SanitizationOrchestrator(_make_config(allowlist=frozenset({"id"})))
    result = orchestrator.sanitize(sample)

    assert sample.columns == source_cols
    assert sample.rows == source_rows
    assert sample.rows is not result.sample.rows


def test_non_disclosure_in_representations() -> None:
    sample = _make_sample(
        columns=("key_col",),
        rows=((_SYNTHETIC_KEY_A,),),
    )
    config = _make_config(key=_SYNTHETIC_KEY_SECRET)
    orchestrator = SanitizationOrchestrator(config)

    assert _SYNTHETIC_KEY_SECRET not in repr(config)
    assert _SYNTHETIC_KEY_SECRET not in str(config)

    result = orchestrator.sanitize(sample)

    assert _SYNTHETIC_KEY_A not in repr(result)
    assert _SYNTHETIC_KEY_A not in str(result)
    assert _SYNTHETIC_KEY_A not in repr(result.sample)
    assert _SYNTHETIC_KEY_A not in str(result.sample)
    assert _SYNTHETIC_KEY_A not in repr(result.report)


def test_mask_action_in_policy() -> None:
    mask_policy = SanitizationPolicy(
        actions={
            SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
            SensitivityClass.PII: SanitizationAction.MASK,
            SensitivityClass.SECRET: SanitizationAction.REDACT,
            SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
            SensitivityClass.UNKNOWN: SanitizationAction.REDACT,
        }
    )
    sample = _make_sample(
        columns=("email",),
        rows=(("user@example.com",),),
    )
    orchestrator = SanitizationOrchestrator(_make_config(policy=mask_policy))
    result = orchestrator.sanitize(sample)

    assert result.sample.rows[_INT_ZERO][_INT_ZERO] == _MASKED_MARKER
    assert result.report.masked_fields == _INT_ONE
    assert result.report.pseudonymized_fields == _INT_ZERO


# ==============================================================================
# Finding 1 Regression: Detached Exception Context & Zero Secret Leakage
# ==============================================================================


def test_finding1_detector_exception_context_is_completely_detached() -> None:
    """Finding 1: Injected secret does not leak in __context__ or traceback."""
    injected_secret = (
        "SUPER_SECRET_TOKEN_IN_DETECTOR_EXCEPTION_XYZ"  # pragma: allowlist secret  # noqa: S105
    )
    sample = _make_sample(
        columns=("id", "email"),
        rows=((_INT_ONE, "alice@example.com"),),
    )
    orchestrator = SanitizationOrchestrator(_make_config())

    with patch.object(
        SecretCredentialDetector,
        "detect",
        side_effect=RuntimeError(f"internal crash with: {injected_secret}"),
    ):
        with pytest.raises(SanitizationOrchestratorError) as exc_info:
            orchestrator.sanitize(sample)

        err = exc_info.value
        assert err.__context__ is None
        assert err.__cause__ is None
        assert injected_secret not in str(err)
        assert injected_secret not in repr(err)

        formatted_tb = "".join(traceback.format_exception(err))
        assert injected_secret not in formatted_tb
        assert "RuntimeError" not in formatted_tb


def test_finding1_transformer_exception_context_is_completely_detached() -> None:
    """Finding 1: Injected secret in transformer does not leak in __context__."""
    injected_secret = "TRANSFORMER_SECRET_KEY_MESSAGE_ABC"  # pragma: allowlist secret  # noqa: S105
    sample = _make_sample(
        columns=("id",),
        rows=((_INT_ONE,),),
    )
    orchestrator = SanitizationOrchestrator(_make_config(allowlist=frozenset({"id"})))

    with patch.object(
        SanitizationTransformer,
        "transform",
        side_effect=RuntimeError(f"transformer failed with: {injected_secret}"),
    ):
        with pytest.raises(SanitizationOrchestratorError) as exc_info:
            orchestrator.sanitize(sample)

        err = exc_info.value
        assert err.__context__ is None
        assert err.__cause__ is None
        assert injected_secret not in str(err)
        assert injected_secret not in repr(err)

        formatted_tb = "".join(traceback.format_exception(err))
        assert injected_secret not in formatted_tb
        assert "RuntimeError" not in formatted_tb


# ==============================================================================
# Finding 2 Regression: Processing-Limit Bypass Prevention
# ==============================================================================


def test_finding2_bypass_mismatched_row_count_rejected() -> None:
    """Finding 2: model_construct with row_count smaller than actual rows fails closed."""
    # Constructed with forged row_count=1, but actual len(rows) = 50
    sample = SampleResult.model_construct(
        schema_name="public",
        table_name="users",
        columns=("col1", "col2"),
        rows=((_INT_ONE, _INT_TWO),) * 50,
        row_count=_INT_ONE,
        truncated=False,
    )
    config = _make_config(max_cells=20)
    orchestrator = SanitizationOrchestrator(config)

    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_finding2_bypass_row_width_mismatch_rejected() -> None:
    """Finding 2: Row with width mismatched against declared columns fails closed."""
    sample = SampleResult.model_construct(
        schema_name="public",
        table_name="users",
        columns=("col1", "col2"),
        rows=((_INT_ONE,),),
        row_count=_INT_ONE,
        truncated=False,
    )
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_finding2_pathological_zero_rows_excessive_fields_rejected() -> None:
    """Finding 2: Zero-row sample exceeding max_fields is bounded and rejected."""
    excessive_fields = 1_500
    columns = tuple(f"col_{i}" for i in range(excessive_fields))
    sample = SampleResult(
        schema_name="public",
        table_name="users",
        columns=columns,
        rows=(),
        row_count=_INT_ZERO,
        truncated=False,
    )
    # Default max_fields is 1,000; sample has 1,500
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_finding2_pathological_zero_columns_excessive_rows_rejected() -> None:
    """Finding 2: Zero-column sample exceeding max_rows is bounded and rejected."""
    excessive_rows = 15_000
    sample = SampleResult(
        schema_name="public",
        table_name="users",
        columns=(),
        rows=((),) * excessive_rows,
        row_count=excessive_rows,
        truncated=False,
    )
    # Default max_rows is 10,000; sample has 15,000
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(sample)


def test_finding2_model_copy_update_bypass_rejected() -> None:
    """Finding 2: model_copy(update=...) forged metadata fails closed."""
    valid_sample = _make_sample(
        columns=("id",),
        rows=((_INT_ONE,),),
    )
    forged = valid_sample.model_copy(update={"row_count": 999})
    orchestrator = SanitizationOrchestrator(_make_config())
    with pytest.raises(SanitizationOrchestratorError):
        orchestrator.sanitize(forged)


# ==============================================================================
# Finding 3 Regression: Bounded Allowlist Iterator
# ==============================================================================


def test_finding3_allowlist_rejects_infinite_iterator_without_hanging() -> None:
    """Finding 3: Infinite iterator is safely bounded and rejected without hanging."""
    with pytest.raises(ValidationError, match="allowlist exceeds maximum allowed entries"):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=itertools.repeat("col"))

    with pytest.raises(ValidationError, match="allowlist exceeds maximum allowed entries"):
        SanitizationOrchestratorConfig(
            non_sensitive_allowlist=(f"c_{i}" for i in itertools.count())
        )


def test_finding3_allowlist_size_cannot_exceed_max_fields() -> None:
    """Finding 3: Allowlist size cannot exceed configured max_fields."""
    with pytest.raises(
        ValidationError,
        match="non_sensitive_allowlist size cannot exceed max_fields",
    ):
        SanitizationOrchestratorConfig(
            max_fields=_INT_THREE,
            non_sensitive_allowlist=["c1", "c2", "c3", "c4"],
        )


def test_finding3_allowlist_rejects_overlong_identifier() -> None:
    """Finding 3: Allowlist entry exceeding maximum identifier length is rejected."""
    long_col = "a" * 129
    with pytest.raises(
        ValidationError,
        match="allowlist entries must be non-empty text without NUL within length limit",
    ):
        SanitizationOrchestratorConfig(non_sensitive_allowlist=[long_col])


# ==============================================================================
# Finding 4 Regression: Accurate Documentation & Payload Serialization
# ==============================================================================


def test_finding4_allowed_values_remain_and_model_dump_not_log_safe() -> None:
    """Finding 4: Approved non-sensitive values remain in sample; model_dump() is not log-safe."""
    sample = _make_sample(
        columns=("item_count", "public_code"),
        rows=((101, "CODE-ABC"),),
    )
    orchestrator = SanitizationOrchestrator(
        _make_config(allowlist=frozenset({"item_count", "public_code"}))
    )
    result = orchestrator.sanitize(sample)

    assert result.sample.rows[_INT_ZERO] == (101, "CODE-ABC")

    assert "CODE-ABC" not in repr(result)
    assert "CODE-ABC" not in repr(result.sample)

    dump = result.model_dump()
    assert dump["sample"]["rows"] == ((101, "CODE-ABC"),)
