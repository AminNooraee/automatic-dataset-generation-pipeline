"""High-value tests for bounded Phase 3C PII detection."""

from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import cast
from uuid import UUID

import pytest
from pydantic import ValidationError

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security import (
    FieldClassification,
    FieldReference,
    PIIDetectionConfig,
    PIIDetectionError,
    PIIDetectionResult,
    PIIDetector,
    SensitivityClass,
)

SENSITIVE_MARKER = "pii-leak-probe-value"


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
    config: PIIDetectionConfig | None = None,
) -> tuple[SensitivityClass, str] | None:
    result = PIIDetector(config or PIIDetectionConfig()).detect(sample((column,), ((value,),)))
    if not result.classifications:
        return None
    finding = result.classifications[0]
    return finding.sensitivity, finding.detector


def test_config_defaults_are_bounded_and_frozen() -> None:
    config = PIIDetectionConfig()

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
            PIIDetectionConfig.model_validate({field_name: value})


def test_harmless_values_have_no_finding_or_non_sensitive_claim() -> None:
    result = PIIDetector().detect(sample(("description",), (("ordinary text",),)))

    assert result.classifications == ()
    assert result.model_dump() == {
        "detector_version": "pii.v1",
        "classifications": (),
        "scanned_fields": 1,
        "scanned_rows": 1,
        "scanned_cells": 1,
    }
    sensitivities: tuple[SensitivityClass, ...] = tuple(
        finding.sensitivity
        for finding in PIIDetector().detect(sample(("email",), (("ordinary",),))).classifications
    )
    assert SensitivityClass.NON_SENSITIVE not in sensitivities


def test_pii_column_names_use_tokenized_matching() -> None:
    for column in ("email", "phone", "telephone", "firstName", "surname", "dob"):
        finding = detect_one("ordinary", column=column)
        assert finding == (SensitivityClass.PII, "pii.column_name")


def test_pii_column_names_cover_person_entity_and_address_contexts() -> None:
    for column in (
        "user_id",
        "customer_id",
        "national_id",
        "passport_number",
        "date_of_birth",
        "first_name",
        "last_name",
        "postal_address",
        "card_number",
        "iban",
        "mac",
        "ipaddress",
        "mobile_number",
    ):
        finding = detect_one("ordinary", column=column)
        assert finding == (SensitivityClass.PII, "pii.column_name")


def test_column_name_look_alikes_are_not_flagged() -> None:
    for column in (
        "name",
        "id",
        "number",
        "order_id",
        "product_id",
        "device_id",
        "status",
        "timestamp",
        "secretary_name",
        "nameplate",
        "mobile_data",
        "mobile_app",
        "zip",
    ):
        assert detect_one("ordinary", column=column) is None


def test_email_value_is_pii() -> None:
    for value in ("user@example.com", "j.smith+tag@sub.domain.co.uk"):
        assert detect_one(value) == (SensitivityClass.PII, "pii.email")
    for value in ("user@example", "user.example.com", "not-an-email"):
        assert detect_one(value) is None


def test_international_phone_value_requires_plus_prefix() -> None:
    for value in ("+14155552671", "+1 415 555 2671"):
        assert detect_one(value) == (SensitivityClass.PII, "pii.phone")
    for value in ("415-555-2671", "+hello", "+1"):
        assert detect_one(value) is None


def test_ip_value_uses_stdlib_parsing() -> None:
    for value in ("192.168.1.1", "2001:db8::ff00:42:8329"):
        assert detect_one(value) == (SensitivityClass.PII, "pii.ip")
    for value in ("999.999.1.1", "192.168.1.1:80", "not an address 192.168.1.1"):
        assert detect_one(value) is None


def test_canonical_mac_value_is_pii() -> None:
    for value in ("00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E"):
        assert detect_one(value) == (SensitivityClass.PII, "pii.mac")
    for value in ("00:1A:2B:3C:4D", "00:1A:2B:3C:4D:5E:6F", "not:00:1A:2B:3C:4D"):
        assert detect_one(value) is None


def test_payment_card_value_requires_length_and_luhn() -> None:
    # Any standalone 13-19 digit, Luhn-valid number is PII, regardless of card brand.
    for value in (
        "4111111111111111",
        "378282246310005",
        "5500005555555559",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "3530111333300000",
        "6200000000000005",
        "6500000000000002",
        "1234567812345670",
    ):
        assert detect_one(value) == (SensitivityClass.PII, "pii.payment_card")
    # Not Luhn-valid, or outside the 13-19 digit standalone-card length range.
    for value in (
        "4111111111111112",
        "1234567890123456",
        "4111111111111111111",
        "411111",
        "1234567812345678901234",
    ):
        assert detect_one(value) is None


def test_iban_value_requires_mod97() -> None:
    assert detect_one("DE89370400440532013000") == (SensitivityClass.PII, "pii.iban")
    invalid_checksum_iban = "DE89370400440532013001"  # pragma: allowlist secret
    for value in (
        invalid_checksum_iban,
        "DE8937040044",
        "DE89 3704 0044 0532 0130 00X",
    ):
        assert detect_one(value) is None


def test_nested_keys_and_values_are_scanned_without_public_key_names() -> None:
    finding = detect_one({"user_email": "synthetic"})

    assert finding == (SensitivityClass.PII, "pii.nested_key")
    assert "user_email" not in repr(finding)


def test_non_string_mapping_key_is_unknown() -> None:
    assert detect_one({1: "ordinary"}) == (SensitivityClass.UNKNOWN, "pii.uninspectable")


def test_container_depth_limit_fails_closed() -> None:
    config = PIIDetectionConfig(max_container_depth=1)

    assert detect_one([["ordinary"]], config=config) == (
        SensitivityClass.UNKNOWN,
        "pii.uninspectable",
    )


def test_container_element_limit_fails_closed() -> None:
    config = PIIDetectionConfig(max_container_elements=2)

    assert detect_one(["one", "two", "three"], config=config) == (
        SensitivityClass.UNKNOWN,
        "pii.uninspectable",
    )


def test_total_container_element_limit_is_inclusive() -> None:
    config = PIIDetectionConfig(max_total_container_elements=4)
    raw_sample = sample(
        ("first", "second", "scalar"),
        ((["one", "two"], ["three", "four"], "ordinary"),),
    )

    result = PIIDetector(config).detect(raw_sample)

    assert result.classifications == ()


def test_total_container_element_limit_plus_one_fails_closed() -> None:
    detector = PIIDetector(PIIDetectionConfig(max_total_container_elements=2))

    with pytest.raises(PIIDetectionError, match="could not complete safely"):
        detector.detect(sample(("payload",), ((["one", "two", "three"],),)))


def test_total_container_element_budget_is_shared_across_cells() -> None:
    config = PIIDetectionConfig(
        max_container_elements=2,
        max_total_container_elements=3,
    )
    raw_sample = sample(("first", "second"), ((["one", "two"], ["three", "four"]),))

    with pytest.raises(PIIDetectionError):
        PIIDetector(config).detect(raw_sample)


def test_total_container_element_error_does_not_leak_raw_value() -> None:
    detector = PIIDetector(PIIDetectionConfig(max_total_container_elements=1))
    raw_sample = sample(("payload",), (([SENSITIVE_MARKER, "overflow"],),))

    with pytest.raises(PIIDetectionError) as captured:
        detector.detect(raw_sample)

    assert str(captured.value) == "PII detection could not complete safely"
    assert SENSITIVE_MARKER not in repr(captured.value)


def test_binary_values_are_bounded_and_strictly_decoded() -> None:
    assert detect_one(b"4111111111111111") == (SensitivityClass.PII, "pii.payment_card")
    assert detect_one(b"\xff") == (SensitivityClass.UNKNOWN, "pii.uninspectable")
    config = PIIDetectionConfig(max_binary_bytes=2)
    assert detect_one(b"abc", config=config) == (
        SensitivityClass.UNKNOWN,
        "pii.uninspectable",
    )
    # Bytes small enough to pass the byte bound but that decode to text over the char bound.
    config = PIIDetectionConfig(max_binary_bytes=16_384, max_text_chars=2)
    assert detect_one(b"abcdef", config=config) == (
        SensitivityClass.UNKNOWN,
        "pii.uninspectable",
    )


def test_empty_and_whitespace_values_are_not_pii() -> None:
    assert detect_one("") is None
    assert detect_one("   ") is None


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
    assert detect_one(object()) == (SensitivityClass.UNKNOWN, "pii.uninspectable")
    config = PIIDetectionConfig(max_text_chars=4)
    assert detect_one("ordinary", config=config) == (
        SensitivityClass.UNKNOWN,
        "pii.uninspectable",
    )


def test_sample_cell_limit_raises_only_safe_error_text() -> None:
    detector = PIIDetector(PIIDetectionConfig(max_cells=1))
    raw_sample = sample(("first", "second"), ((SENSITIVE_MARKER, "ordinary"),))

    with pytest.raises(PIIDetectionError) as captured:
        detector.detect(raw_sample)

    assert str(captured.value) == "PII detection could not complete safely"
    assert SENSITIVE_MARKER not in repr(captured.value)


def test_precedence_one_finding_per_field_and_column_order() -> None:
    raw_sample = sample(
        ("note", "description", "email"),
        (("user@example.com", object(), "ordinary"),),
    )

    result = PIIDetector().detect(raw_sample)

    assert tuple(item.field.column_name for item in result.classifications) == raw_sample.columns
    assert tuple(item.sensitivity for item in result.classifications) == (
        SensitivityClass.PII,
        SensitivityClass.UNKNOWN,
        SensitivityClass.PII,
    )
    assert len(result.classifications) == len({item.field for item in result.classifications})


def test_public_result_never_contains_raw_marker_and_is_frozen() -> None:
    raw_value = f"{SENSITIVE_MARKER}@example.com"
    result = PIIDetector().detect(sample(("payload",), ((raw_value,),)))

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


def test_result_rejects_unsupported_sensitivities() -> None:
    field = FieldReference(schema_name="public", table_name="events", column_name="c")
    for sensitivity in (
        SensitivityClass.CREDENTIAL,
        SensitivityClass.SECRET,
        SensitivityClass.NON_SENSITIVE,
    ):
        finding = FieldClassification(
            field=field,
            sensitivity=sensitivity,
            confidence=0.9,
            detector="pii.column_name",
        )
        with pytest.raises(ValidationError):
            PIIDetectionResult(
                detector_version="pii.v1",
                classifications=(finding,),
                scanned_fields=1,
                scanned_rows=1,
                scanned_cells=1,
            )


def test_result_rejects_inconsistent_scan_counts() -> None:
    field = FieldReference(schema_name="public", table_name="events", column_name="c")
    finding = FieldClassification(
        field=field,
        sensitivity=SensitivityClass.PII,
        confidence=0.9,
        detector="pii.column_name",
    )
    with pytest.raises(ValidationError):
        PIIDetectionResult(
            detector_version="pii.v1",
            classifications=(finding,),
            scanned_fields=1,
            scanned_rows=1,
            scanned_cells=2,
        )
