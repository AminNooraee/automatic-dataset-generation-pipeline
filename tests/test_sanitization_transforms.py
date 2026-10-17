"""High-value tests for bounded Phase 3D value-level sanitization transforms."""

from datetime import UTC, date, datetime, time
from decimal import Decimal
from uuid import UUID

import pytest
from pydantic import SecretStr, ValidationError

from automatic_dataset_generation.security import (
    FieldReference,
    SanitizationAction,
    SanitizationDecision,
    SanitizationTransformConfig,
    SanitizationTransformer,
    SanitizationTransformError,
    SanitizationTransformResult,
    SensitivityClass,
)

_MARKER = "synthetic-sensitive-row-marker"
_LONG_KEY = "k" * 64
_MIN_PSEUDONYM_LENGTH = 32
_MAX_PSEUDONYM_LENGTH = 128
_INT_VALUE = 42
_FLOAT_VALUE = 1.5


def decision(action: SanitizationAction) -> SanitizationDecision:
    field = FieldReference(schema_name="public", table_name="events", column_name="email")
    sensitivity = (
        SensitivityClass.NON_SENSITIVE
        if action is SanitizationAction.ALLOW
        else SensitivityClass.PII
    )
    return SanitizationDecision(
        field=field,
        sensitivity=sensitivity,
        action=action,
        policy_version="1",
        reason_code="policy_mapping",
    )


def run(action: SanitizationAction, value: object) -> SanitizationTransformResult:
    return SanitizationTransformer().transform(value, decision(action))


def transform_pseudonymized(value: object, key: str = _LONG_KEY) -> SanitizationTransformResult:
    return SanitizationTransformer(SanitizationTransformConfig(pseudonymization_key=key)).transform(
        value, decision(SanitizationAction.PSEUDONYMIZE)
    )


def test_config_defaults_are_bounded_and_frozen() -> None:
    config = SanitizationTransformConfig()

    assert config.model_dump() == {
        "max_text_chars": 16_384,
        "max_binary_bytes": 16_384,
        "max_container_depth": 8,
        "max_container_elements": 10_000,
        "pseudonymization_key": None,
    }
    with pytest.raises(ValidationError, match="frozen"):
        config.max_text_chars = 1  # type: ignore[misc]


def test_config_rejects_bool_nonpositive_and_excessive_limits() -> None:
    invalid = (
        ("max_text_chars", True),
        ("max_binary_bytes", 0),
        ("max_container_depth", -1),
        ("max_container_depth", 33),
        ("max_container_elements", 1_000_001),
        ("max_container_elements", 0),
    )
    for field_name, value in invalid:
        with pytest.raises(ValidationError):
            SanitizationTransformConfig.model_validate({field_name: value})


def test_pseudonymization_key_must_be_text() -> None:
    for value in (b"binary", bytearray(b"binary"), 123, True, ["k" * 32]):
        with pytest.raises(ValidationError, match="must be text"):
            SanitizationTransformConfig.model_validate({"pseudonymization_key": value})


def test_pseudonymization_key_length_bounds_are_enforced() -> None:
    with pytest.raises(ValidationError, match="length is out of bounds"):
        SanitizationTransformConfig(pseudonymization_key="k" * 31)
    with pytest.raises(ValidationError, match="length is out of bounds"):
        SanitizationTransformConfig(pseudonymization_key="k" * 4_097)
    # 32 bytes and 4096 bytes are accepted.
    assert SanitizationTransformConfig(pseudonymization_key="k" * 32).pseudonymization_key
    assert SanitizationTransformConfig(pseudonymization_key="k" * 4096).pseudonymization_key


def test_pseudonymization_key_accepts_secret_str_without_disclosure() -> None:
    config = SanitizationTransformConfig(pseudonymization_key=SecretStr(_LONG_KEY))

    assert _LONG_KEY not in repr(config)
    assert _LONG_KEY not in config.model_dump_json()


def test_pseudonymization_key_rejects_hostile_subclasses_without_invocation_or_leak() -> None:
    synthetic_secret = "".join(("synthetic", "-secret-marker-", "x" * 32))

    class HostileStr(str):
        encode_called = False

        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            _ = encoding, errors
            type(self).encode_called = True
            raise ValueError(f"leaked:{self}")

    class HostileSecretStr(SecretStr):
        get_secret_value_called = False

        def get_secret_value(self) -> str:
            type(self).get_secret_value_called = True
            raise ValueError(f"leaked:{synthetic_secret}")

    for hostile_key in (HostileStr(synthetic_secret), HostileSecretStr(synthetic_secret)):
        with pytest.raises(ValidationError) as captured:
            SanitizationTransformConfig(pseudonymization_key=hostile_key)

        assert synthetic_secret not in str(captured.value)
        assert synthetic_secret not in repr(captured.value)

    assert HostileStr.encode_called is False
    assert HostileSecretStr.get_secret_value_called is False


def test_pseudonymization_key_rejects_hostile_str_wrapped_by_exact_secret_str() -> None:
    synthetic_secret = "".join(("synthetic", "-wrapped-secret-marker-", "x" * 32))

    class HostileStr(str):
        encode_called = False

        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            _ = encoding, errors
            type(self).encode_called = True
            raise ValueError(f"leaked:{self}")

    wrapped_key = SecretStr(HostileStr(synthetic_secret))
    assert type(wrapped_key) is SecretStr

    with pytest.raises(ValidationError) as captured:
        SanitizationTransformConfig(pseudonymization_key=wrapped_key)

    assert HostileStr.encode_called is False
    assert synthetic_secret not in str(captured.value)
    assert synthetic_secret not in repr(captured.value)


def test_pseudonymization_key_is_never_disclosed() -> None:
    config = SanitizationTransformConfig(pseudonymization_key=_LONG_KEY)

    assert _LONG_KEY not in repr(config)
    assert _LONG_KEY not in repr(config.pseudonymization_key)
    assert _LONG_KEY not in config.model_dump_json()
    assert config.model_dump()["pseudonymization_key"].get_secret_value() == _LONG_KEY


def test_allow_preserves_in_domain_scalars() -> None:
    assert run(SanitizationAction.ALLOW, _INT_VALUE).value == _INT_VALUE
    assert run(SanitizationAction.ALLOW, _FLOAT_VALUE).value == _FLOAT_VALUE
    assert run(SanitizationAction.ALLOW, value=True).value is True
    assert run(SanitizationAction.ALLOW, "hello").value == "hello"
    assert run(SanitizationAction.ALLOW, None).value is None
    assert run(SanitizationAction.ALLOW, _INT_VALUE).dropped is False


def test_allow_rejects_non_finite_float() -> None:
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(SanitizationTransformError, match="could not complete safely"):
            run(SanitizationAction.ALLOW, value)


def test_allow_normalizes_supported_scalars_to_sanitized_domain() -> None:
    assert run(SanitizationAction.ALLOW, Decimal("1.50")).value == "1.50"
    assert run(SanitizationAction.ALLOW, date(2026, 1, 2)).value == "2026-01-02"
    assert run(SanitizationAction.ALLOW, time(1, 2, 3)).value == "01:02:03"
    assert (
        run(
            SanitizationAction.ALLOW,
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        ).value
        == "2026-01-02T03:04:05+00:00"
    )
    assert run(SanitizationAction.ALLOW, UUID(int=1)).value == str(UUID(int=1))
    assert run(SanitizationAction.ALLOW, b"plain").value == "plain"


def test_allow_rejects_arbitrary_and_unsafe_objects() -> None:
    for value in (object(), [1], (1, 2), {"a": 1}, float("nan"), Decimal("NaN"), b"\xff"):
        with pytest.raises(SanitizationTransformError, match="could not complete safely"):
            run(SanitizationAction.ALLOW, value)


def test_allow_rejects_oversized_binary_and_decoded_text() -> None:
    byte_limited = SanitizationTransformer(SanitizationTransformConfig(max_binary_bytes=2))
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        byte_limited.transform(b"abcdef", decision(SanitizationAction.ALLOW))
    char_limited = SanitizationTransformer(
        SanitizationTransformConfig(max_binary_bytes=16_384, max_text_chars=2)
    )
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        char_limited.transform(b"abcdef", decision(SanitizationAction.ALLOW))
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        char_limited.transform("abcdef", decision(SanitizationAction.ALLOW))


def test_redact_returns_fixed_marker_without_revealing_length_or_type() -> None:
    for value in ("short", "x" * 500, 42, True, b"abcd", object()):
        result = run(SanitizationAction.REDACT, value)

        assert result.value == "[REDACTED]"
        assert isinstance(result.value, str)


def test_redact_of_none_is_none() -> None:
    assert run(SanitizationAction.REDACT, None).value is None


def test_mask_returns_fixed_marker_without_revealing_length_or_type() -> None:
    for value in ("short", "x" * 500, 42, b"abcd"):
        assert run(SanitizationAction.MASK, value).value == "[MASKED]"
    assert run(SanitizationAction.MASK, None).value is None


def test_drop_is_distinguishable_from_genuine_none() -> None:
    dropped = run(SanitizationAction.DROP, "any")

    assert dropped.dropped is True
    assert dropped.value is None
    assert run(SanitizationAction.ALLOW, None).value is None
    assert run(SanitizationAction.ALLOW, None).dropped is False


def test_pseudonymize_is_deterministic_and_bounded() -> None:
    first = transform_pseudonymized("alice@example.com").value
    second = transform_pseudonymized("alice@example.com").value

    assert first == second
    assert isinstance(first, str)
    assert first.startswith("psn_v1_")
    assert _MIN_PSEUDONYM_LENGTH < len(first) < _MAX_PSEUDONYM_LENGTH
    assert _MARKER not in first


def test_pseudonymize_is_stable_within_config_but_key_sensitive() -> None:
    a = transform_pseudonymized("alice@example.com", key="k" * 32).value
    b = transform_pseudonymized("alice@example.com", key="j" * 32).value

    assert a != b


def test_pseudonymize_requires_a_configured_key() -> None:
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        SanitizationTransformer().transform("alice", decision(SanitizationAction.PSEUDONYMIZE))


def test_pseudonymize_is_collision_safe_across_types() -> None:
    values = (1, "1", True, "true", 1.0, Decimal(1), b"1", (1,), [1], {"a": 1}, None)

    encoded = {transform_pseudonymized(value).value for value in values}

    assert len(encoded) == len(values)


def test_pseudonymize_of_none_is_none() -> None:
    assert transform_pseudonymized(None).value is None


def test_pseudonymize_supports_json_safe_and_safe_scalars() -> None:
    for value in (42, 1.5, True, "text", Decimal("3.14"), date(2020, 1, 1), time(1, 2, 3)):
        result = transform_pseudonymized(value)

        assert isinstance(result.value, str)
        assert result.value.startswith("psn_v1_")


def test_pseudonymize_handles_nested_structures_deterministically() -> None:
    value = {"a": [1, {"b": "c", "d": 2}], "e": "f"}

    assert (
        transform_pseudonymized(value).value
        == transform_pseudonymized({"a": [1, {"d": 2, "b": "c"}], "e": "f"}).value
    )


def test_pseudonymize_frames_nested_containers_without_shape_collisions() -> None:
    assert transform_pseudonymized([[], []]).value != transform_pseudonymized([[[]]]).value


def test_pseudonymize_rejects_non_string_mapping_keys() -> None:
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transform_pseudonymized({1: "value"})
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transform_pseudonymized({("a", 1): "value"})


def test_pseudonymize_rejects_arbitrary_and_unsafe_objects() -> None:
    for value in (object(), float("nan"), Decimal("NaN"), float("inf")):
        with pytest.raises(SanitizationTransformError, match="could not complete safely"):
            transform_pseudonymized(value)


def test_unsupported_scalar_subclass_is_not_stringified() -> None:
    class HostileInt(int):
        stringified = False

        def __str__(self) -> str:
            type(self).stringified = True
            raise AssertionError("must not stringify raw values")

    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transform_pseudonymized(HostileInt(1))

    assert HostileInt.stringified is False


def test_pseudonymize_key_none_is_default() -> None:
    # An explicit None key is equivalent to the default (no key configured).
    assert SanitizationTransformConfig(pseudonymization_key=None).pseudonymization_key is None
    assert SanitizationTransformConfig().pseudonymization_key is None


def test_pseudonymize_covers_all_supported_scalar_tags_in_containers() -> None:
    # Each supported scalar type inside a container exercises a distinct canonical branch.
    value = [
        None,
        False,
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        date(2026, 1, 2),
        time(3, 4, 5),
        UUID(int=2),
        b"raw",
    ]

    assert transform_pseudonymized(value).value == transform_pseudonymized(list(value)).value


def test_pseudonymize_accepts_safe_binary_scalars() -> None:
    result = transform_pseudonymized(b"\xff")

    assert isinstance(result.value, str)
    assert result.value.startswith("psn_v1_")


def test_container_element_limit_fails_closed() -> None:
    config = SanitizationTransformConfig(
        max_container_elements=3,
        pseudonymization_key=_LONG_KEY,
    )
    transformer = SanitizationTransformer(config)

    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transformer.transform([1, 2, 3, 4, 5, 6], decision(SanitizationAction.PSEUDONYMIZE))


def test_container_element_limit_is_shared_and_inclusive() -> None:
    config = SanitizationTransformConfig(
        max_container_elements=4,
        pseudonymization_key=_LONG_KEY,
    )
    transformer = SanitizationTransformer(config)

    assert transformer.transform([1, [2, 3]], decision(SanitizationAction.PSEUDONYMIZE)).value
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transformer.transform([1, [2, 3, 4]], decision(SanitizationAction.PSEUDONYMIZE))


def test_container_depth_limit_fails_closed() -> None:
    config = SanitizationTransformConfig(max_container_depth=1, pseudonymization_key=_LONG_KEY)
    transformer = SanitizationTransformer(config)

    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transformer.transform([[1]], decision(SanitizationAction.PSEUDONYMIZE))
    with pytest.raises(SanitizationTransformError, match="could not complete safely"):
        transformer.transform([[]], decision(SanitizationAction.PSEUDONYMIZE))

    assert transformer.transform([1], decision(SanitizationAction.PSEUDONYMIZE)).value


def test_oversized_text_and_binary_fail_closed() -> None:
    config = SanitizationTransformConfig(
        max_text_chars=4, max_binary_bytes=4, pseudonymization_key=_LONG_KEY
    )
    transformer = SanitizationTransformer(config)

    with pytest.raises(SanitizationTransformError):
        transformer.transform("way too long", decision(SanitizationAction.PSEUDONYMIZE))
    with pytest.raises(SanitizationTransformError):
        transformer.transform(b"way too long", decision(SanitizationAction.PSEUDONYMIZE))


def test_result_hides_value_from_repr_but_keeps_it_in_dump() -> None:
    result = SanitizationTransformer().transform(_MARKER, decision(SanitizationAction.ALLOW))

    assert _MARKER not in repr(result)
    assert result.model_dump()["value"] == _MARKER
    assert result.model_dump(mode="json")["value"] == _MARKER


def test_result_rejects_unsafe_value_domain() -> None:
    for value in (b"bytes", Decimal("1.2"), object(), [1], float("nan")):
        with pytest.raises(ValidationError):
            SanitizationTransformResult(
                action=SanitizationAction.ALLOW,
                value=value,
                dropped=False,
                transformer_version="sanitization_transform.v1",
            )


def test_result_enforces_action_dropped_consistency() -> None:
    base = {"transformer_version": "sanitization_transform.v1"}

    # Drop requires dropped and no value.
    with pytest.raises(ValidationError):
        SanitizationTransformResult(
            action=SanitizationAction.DROP, value=None, dropped=False, **base
        )
    # Redact/mark require a marker value (None is reserved for a null input).
    for action in (SanitizationAction.REDACT, SanitizationAction.MASK):
        with pytest.raises(ValidationError):
            SanitizationTransformResult(action=action, value="not a marker", dropped=False, **base)
    with pytest.raises(ValidationError):
        SanitizationTransformResult(
            action=SanitizationAction.REDACT, value="[MASKED]", dropped=False, **base
        )
    with pytest.raises(ValidationError):
        SanitizationTransformResult(
            action=SanitizationAction.MASK, value="[REDACTED]", dropped=False, **base
        )
    for value in (1, "raw value", "psn_v1_too_short"):
        with pytest.raises(ValidationError):
            SanitizationTransformResult(
                action=SanitizationAction.PSEUDONYMIZE,
                value=value,
                dropped=False,
                **base,
            )
    # A dropped result cannot carry a value.
    with pytest.raises(ValidationError):
        SanitizationTransformResult(action=SanitizationAction.DROP, value="x", dropped=True, **base)
    # Non-drop cannot be dropped.
    with pytest.raises(ValidationError):
        SanitizationTransformResult(action=SanitizationAction.ALLOW, value=1, dropped=True, **base)


def test_result_rejects_unknown_action_and_version() -> None:
    with pytest.raises(ValidationError):
        SanitizationTransformResult(
            action="scramble",
            value=1,
            dropped=False,
            transformer_version="bad version",
        )


def test_transformer_requires_a_decision_instance() -> None:
    with pytest.raises(TypeError, match="SanitizationDecision"):
        SanitizationTransformer().transform("value", "not a decision")  # type: ignore[arg-type]
