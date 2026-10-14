"""High-value tests for bounded Phase 3B secret and credential detection."""

from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import cast
from uuid import UUID

import pytest
from pydantic import ValidationError

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security import (
    SecretCredentialDetector,
    SecretDetectionConfig,
    SecretDetectionError,
    SensitivityClass,
)

SENSITIVE_MARKER = "synthetic-sensitive-marker"


def sample(
    columns: tuple[str, ...],
    rows: tuple[tuple[object, ...], ...],
) -> SampleResult:
    return SampleResult(
        schema_name="public",
        table_name="events",
        columns=columns,
        rows=rows,
        row_count=len(rows),
        truncated=False,
    )


def detect_one(
    value: object,
    *,
    column: str = "payload",
    config: SecretDetectionConfig | None = None,
) -> tuple[SensitivityClass, str] | None:
    result = SecretCredentialDetector(config or SecretDetectionConfig()).detect(
        sample((column,), ((value,),))
    )
    if not result.classifications:
        return None
    finding = result.classifications[0]
    return finding.sensitivity, finding.detector


def test_config_defaults_are_bounded_and_frozen() -> None:
    config = SecretDetectionConfig()

    assert config.model_dump() == {
        "max_cells": 10_000,
        "max_text_chars": 16_384,
        "max_binary_bytes": 16_384,
        "max_container_depth": 8,
        "max_container_elements": 10_000,
        "max_total_container_elements": 100_000,
    }
    with pytest.raises(ValidationError, match="frozen"):
        config.max_cells = 1  # type: ignore[misc]


def test_config_rejects_bool_nonpositive_and_excessive_limits() -> None:
    invalid = (
        ("max_cells", True),
        ("max_text_chars", 0),
        ("max_binary_bytes", -1),
        ("max_container_depth", 33),
        ("max_container_elements", 1_000_001),
        ("max_total_container_elements", True),
        ("max_total_container_elements", 0),
        ("max_total_container_elements", 10_000_001),
    )
    for field_name, value in invalid:
        with pytest.raises(ValidationError):
            SecretDetectionConfig.model_validate({field_name: value})


def test_harmless_values_have_no_finding_or_non_sensitive_claim() -> None:
    result = SecretCredentialDetector().detect(sample(("description",), (("ordinary text",),)))

    assert result.classifications == ()
    assert result.model_dump() == {
        "detector_version": "secret_credential.v1",
        "classifications": (),
        "scanned_fields": 1,
        "scanned_rows": 1,
        "scanned_cells": 1,
    }
    sensitivities: tuple[SensitivityClass, ...] = tuple(
        finding.sensitivity
        for finding in SecretCredentialDetector()
        .detect(sample(("password",), (("ordinary",),)))
        .classifications
    )
    assert SensitivityClass.NON_SENSITIVE not in sensitivities


def test_credential_column_names_use_tokenized_matching() -> None:
    for column in ("password", "api_key", "apiKey", "access-token", "client_secret"):
        finding = detect_one("ordinary", column=column)
        assert finding == (SensitivityClass.CREDENTIAL, "secret_credential.column_name")


def test_secret_column_names_are_distinct_from_credentials() -> None:
    for column in ("private_key", "signingKey", "secret"):
        finding = detect_one("ordinary", column=column)
        assert finding == (SensitivityClass.SECRET, "secret_credential.column_name")


def test_column_name_false_positives_are_not_classified() -> None:
    for column in ("secretary_name", "monkey", "key", "salt", "client_id"):
        assert detect_one("ordinary", column=column) is None


def test_pem_private_key_header_is_secret() -> None:
    pem_label = "PRIVATE" + " KEY"
    value = f"-----BEGIN {pem_label}-----\nsynthetic\n-----END {pem_label}-----"

    assert detect_one(value) == (
        SensitivityClass.SECRET,
        "secret_credential.private_key",
    )


def test_authorization_header_values_are_credentials() -> None:
    values = (
        "Bearer syntheticCredential123",  # pragma: allowlist secret
        "Basic c3ludGhldGljOnZhbHVl",  # pragma: allowlist secret
    )
    for value in values:
        assert detect_one(value) == (
            SensitivityClass.CREDENTIAL,
            "secret_credential.auth_header",
        )


def test_jwt_like_structure_is_conservative() -> None:
    jwt = (
        "eyJhbGciOiJub25l.eyJzdWIiOiJzeW50aGV0aWMifQ.syntheticSignature"  # pragma: allowlist secret
    )

    assert detect_one(jwt) == (SensitivityClass.CREDENTIAL, "secret_credential.jwt")
    assert detect_one("release.version.txt") is None


def test_uri_userinfo_requires_a_nonempty_password() -> None:
    uri = (
        "postgresql://synthetic-user:synthetic-pass@example.invalid/db"  # pragma: allowlist secret
    )

    assert detect_one(uri) == (
        SensitivityClass.CREDENTIAL,
        "secret_credential.uri_userinfo",
    )
    assert detect_one("postgresql://synthetic-user@example.invalid/db") is None


def test_key_value_and_json_like_assignments_are_credentials() -> None:
    values = (
        "password=synthetic-value",  # pragma: allowlist secret
        'settings {"api_key": "synthetic-value"}',  # pragma: allowlist secret
    )
    for value in values:
        assert detect_one(value) == (
            SensitivityClass.CREDENTIAL,
            "secret_credential.key_value",
        )


def test_nested_keys_and_values_are_scanned_without_public_key_names() -> None:
    value = {"outer": [{"password": "synthetic-value"}]}  # pragma: allowlist secret

    finding = detect_one(value)

    assert finding == (SensitivityClass.CREDENTIAL, "secret_credential.nested_key")
    assert "password" not in repr(finding)


def test_non_string_mapping_key_is_unknown() -> None:
    assert detect_one({1: "ordinary"}) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )


def test_container_depth_limit_fails_closed() -> None:
    config = SecretDetectionConfig(max_container_depth=1)

    assert detect_one([["ordinary"]], config=config) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )


def test_container_element_limit_fails_closed() -> None:
    config = SecretDetectionConfig(max_container_elements=2)

    assert detect_one(["one", "two", "three"], config=config) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )


def test_total_container_element_limit_is_inclusive() -> None:
    config = SecretDetectionConfig(max_total_container_elements=4)
    raw_sample = sample(
        ("first", "second", "scalar"),
        ((["one", "two"], ["three", "four"], "ordinary"),),
    )

    result = SecretCredentialDetector(config).detect(raw_sample)

    assert result.classifications == ()


def test_total_container_element_limit_plus_one_fails_closed() -> None:
    detector = SecretCredentialDetector(SecretDetectionConfig(max_total_container_elements=2))

    with pytest.raises(SecretDetectionError, match="could not complete safely"):
        detector.detect(sample(("payload",), ((["one", "two", "three"],),)))


def test_total_container_element_budget_is_shared_across_cells() -> None:
    config = SecretDetectionConfig(
        max_container_elements=2,
        max_total_container_elements=3,
    )
    raw_sample = sample(("first", "second"), ((["one", "two"], ["three", "four"]),))

    with pytest.raises(SecretDetectionError):
        SecretCredentialDetector(config).detect(raw_sample)


def test_total_container_element_error_does_not_leak_raw_value() -> None:
    detector = SecretCredentialDetector(SecretDetectionConfig(max_total_container_elements=1))
    raw_sample = sample(("payload",), (([SENSITIVE_MARKER, "overflow"],),))

    with pytest.raises(SecretDetectionError) as captured:
        detector.detect(raw_sample)

    assert str(captured.value) == "Secret and credential detection could not complete safely"
    assert SENSITIVE_MARKER not in repr(captured.value)


def test_binary_values_are_bounded_and_strictly_decoded() -> None:
    assert detect_one(b"password=synthetic-value") == (  # pragma: allowlist secret
        SensitivityClass.CREDENTIAL,
        "secret_credential.key_value",
    )
    assert detect_one(b"\xff") == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )
    config = SecretDetectionConfig(max_binary_bytes=2)
    assert detect_one(b"abc", config=config) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )


def test_known_nontext_scalars_are_not_stringified() -> None:
    values = (
        None,
        True,
        42,
        1.5,
        Decimal("1.2"),
        date(2026, 1, 1),
        datetime(2026, 1, 1, tzinfo=UTC),
        time(12, 0),
        UUID("00000000-0000-0000-0000-000000000001"),
    )
    for value in values:
        assert detect_one(value) is None


def test_unsupported_object_and_oversized_text_are_unknown() -> None:
    assert detect_one(object()) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )
    config = SecretDetectionConfig(max_text_chars=4)
    assert detect_one("ordinary", config=config) == (
        SensitivityClass.UNKNOWN,
        "secret_credential.uninspectable",
    )


def test_sample_cell_limit_raises_only_safe_error_text() -> None:
    detector = SecretCredentialDetector(SecretDetectionConfig(max_cells=1))
    raw_sample = sample(("first", "second"), ((SENSITIVE_MARKER, "ordinary"),))

    with pytest.raises(SecretDetectionError) as captured:
        detector.detect(raw_sample)

    assert str(captured.value) == "Secret and credential detection could not complete safely"
    assert SENSITIVE_MARKER not in repr(captured.value)


def test_precedence_one_finding_per_field_and_column_order() -> None:
    pem_label = "PRIVATE" + " KEY"
    private_key = f"-----BEGIN {pem_label}-----"
    credential = "Bearer syntheticCredential123"  # pragma: allowlist secret
    raw_sample = sample(
        ("unknown_value", "secret_value", "password"),
        ((object(), private_key, private_key), ("ordinary", object(), credential)),
    )

    result = SecretCredentialDetector().detect(raw_sample)

    assert tuple(item.field.column_name for item in result.classifications) == raw_sample.columns
    assert tuple(item.sensitivity for item in result.classifications) == (
        SensitivityClass.UNKNOWN,
        SensitivityClass.SECRET,
        SensitivityClass.CREDENTIAL,
    )
    assert len(result.classifications) == len({item.field for item in result.classifications})


def test_public_result_never_contains_raw_marker_and_is_frozen() -> None:
    raw_value = f"password={SENSITIVE_MARKER}"  # pragma: allowlist secret
    result = SecretCredentialDetector().detect(sample(("payload",), ((raw_value,),)))

    assert SENSITIVE_MARKER not in repr(result)
    assert SENSITIVE_MARKER not in str(result.model_dump(mode="json"))
    assert set(type(result).model_fields) == {
        "detector_version",
        "classifications",
        "scanned_fields",
        "scanned_rows",
        "scanned_cells",
    }
    with pytest.raises(ValidationError, match="frozen"):
        cast("object", result).scanned_cells = 0  # type: ignore[attr-defined]
