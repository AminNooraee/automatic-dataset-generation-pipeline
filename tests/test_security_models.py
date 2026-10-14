"""High-value tests for Phase 3A security contracts and policy invariants."""

from decimal import Decimal
from typing import cast

import pytest
from pydantic import ValidationError

from automatic_dataset_generation.security import (
    FieldClassification,
    FieldReference,
    SanitizationAction,
    SanitizationDecision,
    SanitizationPolicy,
    SanitizationReport,
    SanitizedSample,
    SensitivityClass,
)

SENSITIVE_MARKER = "synthetic-sensitive-row-marker"
EXPECTED_TOTAL_FIELDS = 6


def field() -> FieldReference:
    return FieldReference(schema_name="public", table_name="events", column_name="email")


def default_actions() -> dict[SensitivityClass, SanitizationAction]:
    return {
        SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
        SensitivityClass.PII: SanitizationAction.PSEUDONYMIZE,
        SensitivityClass.SECRET: SanitizationAction.REDACT,
        SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
        SensitivityClass.UNKNOWN: SanitizationAction.REDACT,
    }


def test_enum_values_are_stable() -> None:
    assert tuple(item.value for item in SensitivityClass) == (
        "non_sensitive",
        "pii",
        "secret",
        "credential",
        "unknown",
    )
    assert tuple(item.value for item in SanitizationAction) == (
        "allow",
        "redact",
        "mask",
        "pseudonymize",
        "drop",
    )


def test_default_policy_is_complete_and_fail_closed() -> None:
    policy = SanitizationPolicy()

    assert policy.policy_version == "1"
    assert {item: policy.action_for(item) for item in SensitivityClass} == default_actions()
    assert policy.model_dump(mode="json") == {
        "policy_version": "1",
        "actions": {key.value: value.value for key, value in default_actions().items()},
    }
    assert SanitizationPolicy.model_validate(policy.model_dump(mode="json")) == policy


def test_policy_rejects_allow_for_sensitive_or_unknown() -> None:
    for sensitivity in (
        SensitivityClass.PII,
        SensitivityClass.SECRET,
        SensitivityClass.CREDENTIAL,
        SensitivityClass.UNKNOWN,
    ):
        actions = default_actions()
        actions[sensitivity] = SanitizationAction.ALLOW

        with pytest.raises(ValidationError, match="cannot allow"):
            SanitizationPolicy(actions=actions)


def test_policy_rejects_missing_unknown_and_invalid_action_entries() -> None:
    missing = default_actions()
    missing.pop(SensitivityClass.UNKNOWN)
    with pytest.raises(ValidationError, match="every sensitivity"):
        SanitizationPolicy(actions=missing)

    with pytest.raises(ValidationError):
        SanitizationPolicy.model_validate(
            {"actions": {**default_actions(), "future_class": "redact"}}
        )

    with pytest.raises(ValidationError):
        SanitizationPolicy.model_validate(
            {"actions": {**default_actions(), SensitivityClass.PII: "scramble"}}
        )


def test_policy_model_and_mapping_are_immutable() -> None:
    policy = SanitizationPolicy()
    field_name = "policy_version"

    with pytest.raises(ValidationError, match="frozen"):
        setattr(policy, field_name, "2")
    mutable_view = cast("dict[SensitivityClass, SanitizationAction]", policy.actions)
    with pytest.raises(TypeError):
        mutable_view[SensitivityClass.PII] = SanitizationAction.DROP


def test_policy_defensively_copies_constructor_actions() -> None:
    actions = default_actions()
    policy = SanitizationPolicy(actions=actions)

    actions[SensitivityClass.PII] = SanitizationAction.DROP

    assert policy.action_for(SensitivityClass.PII) is SanitizationAction.PSEUDONYMIZE


def test_field_reference_accepts_unicode_spaces_punctuation_without_normalizing() -> None:
    reference = FieldReference(
        schema_name="Odd Schema",
        table_name="رویداد!",
        column_name='Mixed " Column',
    )

    assert reference.model_dump() == {
        "schema_name": "Odd Schema",
        "table_name": "رویداد!",
        "column_name": 'Mixed " Column',
    }


def test_field_reference_rejects_empty_or_nul() -> None:
    for value in ("", "has\x00nul"):
        with pytest.raises(ValidationError):
            FieldReference(schema_name=value, table_name="events", column_name="id")


def test_classification_accepts_confidence_boundaries() -> None:
    for confidence in (0, 1, 0.5):
        classification = FieldClassification(
            field=field(),
            sensitivity=SensitivityClass.PII,
            confidence=confidence,
            detector="schema_hint_v1",
        )

        assert classification.confidence == float(confidence)


def test_classification_rejects_invalid_confidence() -> None:
    for confidence in (-0.1, 1.1, float("nan"), float("inf"), True, "0.5"):
        with pytest.raises(ValidationError, match="confidence"):
            FieldClassification.model_validate(
                {
                    "field": field(),
                    "sensitivity": SensitivityClass.PII,
                    "confidence": confidence,
                    "detector": "schema_hint_v1",
                }
            )


def test_classification_contains_metadata_only() -> None:
    classification = FieldClassification(
        field=field(),
        sensitivity=SensitivityClass.UNKNOWN,
        confidence=0.0,
        detector="fallback",
    )

    assert set(FieldClassification.model_fields) == {
        "field",
        "sensitivity",
        "confidence",
        "detector",
    }
    assert SENSITIVE_MARKER not in repr(classification)


def test_policy_decision_is_deterministic_and_carries_lineage() -> None:
    classification = FieldClassification(
        field=field(),
        sensitivity=SensitivityClass.PII,
        confidence=0.8,
        detector="schema_hint_v1",
    )

    first = SanitizationPolicy(policy_version="policy-v1").decide(classification)
    second = SanitizationPolicy(policy_version="policy-v1").decide(classification)

    assert first == second
    assert first.action is SanitizationAction.PSEUDONYMIZE
    assert first.policy_version == "policy-v1"
    assert first.reason_code == "policy_mapping"


def test_decision_rejects_allow_for_non_safe_classification() -> None:
    with pytest.raises(ValidationError, match="not permitted"):
        SanitizationDecision(
            field=field(),
            sensitivity=SensitivityClass.UNKNOWN,
            action=SanitizationAction.ALLOW,
            policy_version="1",
            reason_code="policy_mapping",
        )


def test_sanitized_sample_accepts_only_explicit_scalar_domain() -> None:
    sample = SanitizedSample(
        schema_name="public",
        table_name="events",
        columns=("none", "flag", "count", "score", "text"),
        rows=((None, True, 3, 1.5, "safe"),),
        row_count=1,
        truncated=False,
        policy_version="1",
    )

    assert sample.rows == ((None, True, 3, 1.5, "safe"),)


def test_sanitized_sample_validates_shape_count_and_columns() -> None:
    with pytest.raises(ValidationError, match="row_count"):
        SanitizedSample(
            schema_name="public",
            table_name="events",
            columns=("id",),
            rows=((1,),),
            row_count=0,
            truncated=False,
            policy_version="1",
        )
    with pytest.raises(ValidationError, match="match the declared columns"):
        SanitizedSample(
            schema_name="public",
            table_name="events",
            columns=("id", "name"),
            rows=((1,),),
            row_count=1,
            truncated=False,
            policy_version="1",
        )
    with pytest.raises(ValidationError, match="unique"):
        SanitizedSample(
            schema_name="public",
            table_name="events",
            columns=("id", "id"),
            rows=((1, 2),),
            row_count=1,
            truncated=False,
            policy_version="1",
        )


def test_sanitized_sample_rejects_non_json_safe_objects() -> None:
    for value in (b"bytes", memoryview(b"view"), Decimal("1.2"), object()):
        with pytest.raises(ValidationError):
            SanitizedSample(
                schema_name="public",
                table_name="events",
                columns=("value",),
                rows=((value,),),  # type: ignore[arg-type]
                row_count=1,
                truncated=False,
                policy_version="1",
            )


def test_sanitized_sample_rejects_non_finite_float() -> None:
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="finite"):
            SanitizedSample(
                schema_name="public",
                table_name="events",
                columns=("value",),
                rows=((value,),),
                row_count=1,
                truncated=False,
                policy_version="1",
            )


def test_sanitized_rows_are_hidden_from_repr() -> None:
    sample = SanitizedSample(
        schema_name="public",
        table_name="events",
        columns=("value",),
        rows=((SENSITIVE_MARKER,),),
        row_count=1,
        truncated=False,
        policy_version="1",
    )

    assert SENSITIVE_MARKER not in repr(sample)
    assert sample.rows == ((SENSITIVE_MARKER,),)


def test_report_accepts_consistent_non_sensitive_counts() -> None:
    report = SanitizationReport(
        policy_version="1",
        total_fields=6,
        classified_fields=5,
        redacted_fields=2,
        masked_fields=1,
        pseudonymized_fields=1,
        dropped_fields=0,
        allowed_fields=1,
        unknown_fields=1,
    )

    assert report.total_fields == EXPECTED_TOTAL_FIELDS
    assert report.model_dump()["unknown_fields"] == 1

    all_unknown_report = SanitizationReport(
        policy_version="1",
        total_fields=2,
        classified_fields=2,
        redacted_fields=2,
        unknown_fields=2,
    )
    assert all_unknown_report.unknown_fields == all_unknown_report.classified_fields


def test_report_rejects_negative_or_inconsistent_counts() -> None:
    with pytest.raises(ValidationError):
        SanitizationReport(policy_version="1", total_fields=-1, classified_fields=0)
    with pytest.raises(ValidationError, match="inconsistent"):
        SanitizationReport(
            policy_version="1",
            total_fields=2,
            classified_fields=2,
            redacted_fields=1,
        )
    with pytest.raises(ValidationError, match="inconsistent"):
        SanitizationReport(
            policy_version="1",
            total_fields=2,
            classified_fields=1,
            redacted_fields=1,
            unknown_fields=2,
        )


def test_public_contracts_have_no_secret_storage_or_raw_value_fields() -> None:
    forbidden_fragments = ("secret", "salt", "key", "token", "password", "credential", "raw")
    model_types = (
        FieldReference,
        FieldClassification,
        SanitizationDecision,
        SanitizationPolicy,
        SanitizedSample,
        SanitizationReport,
    )

    field_names = {name for model_type in model_types for name in model_type.model_fields}
    assert not any(fragment in name for fragment in forbidden_fragments for name in field_names)
