"""Deterministic, bounded Phase 3D sanitization transform primitives.

Phase 3D takes one raw value and one already-resolved ``SanitizationDecision`` and applies
exactly that action. It does not decide sensitivity, run detectors, merge findings, build a
``SanitizedSample``, or validate leakage. It executes the action chosen by ``SanitizationPolicy``
(ADR 3A) over a single cell, fail-closed and leak-free.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from typing import Self, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from automatic_dataset_generation.security.models import (
    SanitizationAction,
    SanitizationDecision,
    SanitizedValue,
)

_SAFE_ERROR_MESSAGE = "Sanitization transform could not complete safely"
_TRANSFORMER_VERSION = "sanitization_transform.v1"
# Versioned HMAC namespace: mixed into the pseudonym message so the scheme is versioned and a
# future algorithm change cannot reproduce old tokens.
_DOMAIN_SEPARATOR = b"automatic-dataset-generation:pseudonym:v1"
_PSEUDONYM_PREFIX = "psn_v1_"
_PSEUDONYM_PATTERN = re.compile(r"^psn_v1_[A-Za-z0-9_-]{43}$")
_REDACTED_MARKER = "[REDACTED]"
_MASKED_MARKER = "[MASKED]"

_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 4_096

# Hard ceilings align with the Phase 3B/3C detector limits.
_MAX_TEXT_CHARS = 1_000_000
_MAX_BINARY_BYTES = 1_000_000
_MAX_CONTAINER_DEPTH = 32
_MAX_CONTAINER_ELEMENTS = 1_000_000

# Type tags for the collision-safe canonical encoding.
_TAG_NULL = 0
_TAG_TRUE = 1
_TAG_FALSE = 2
_TAG_INT = 3
_TAG_FLOAT = 4
_TAG_STR = 5
_TAG_DECIMAL = 6
_TAG_DATE = 7
_TAG_DATETIME = 8
_TAG_TIME = 9
_TAG_UUID = 10
_TAG_BYTES = 11
_TAG_LIST = 12
_TAG_TUPLE = 13
_TAG_MAPPING = 14


class SanitizationTransformError(RuntimeError):
    """Safe public failure raised when a transform cannot complete without unsafe work."""


class SanitizationTransformConfig(BaseModel):
    """Immutable, per-value resource limits and optional pseudonymization key.

    The key is optional because ``allow``/``redact``/``mask``/``drop`` never need it. It is a
    ``SecretStr``; it is never shown in ``repr`` or ``model_dump`` and never appears in errors.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    max_text_chars: int = Field(default=16_384, gt=0, le=_MAX_TEXT_CHARS, strict=True)
    max_binary_bytes: int = Field(default=16_384, gt=0, le=_MAX_BINARY_BYTES, strict=True)
    max_container_depth: int = Field(default=8, gt=0, le=_MAX_CONTAINER_DEPTH, strict=True)
    max_container_elements: int = Field(
        default=10_000,
        gt=0,
        le=_MAX_CONTAINER_ELEMENTS,
        strict=True,
    )
    pseudonymization_key: SecretStr | None = Field(default=None, repr=False)

    @field_validator("pseudonymization_key", mode="before")
    @classmethod
    def _validate_key(cls, value: object) -> object:
        if value is None:
            return value
        # SecretStr would otherwise coerce bytes/bytearray to text; reject any non-str.
        if type(value) is SecretStr:
            key_text = value.get_secret_value()
            if type(key_text) is not str:
                raise ValueError("pseudonymization key must be text")
        elif type(value) is str:
            key_text = value
        else:
            raise ValueError("pseudonymization key must be text")
        key_bytes = key_text.encode("utf-8")
        if not _MIN_KEY_BYTES <= len(key_bytes) <= _MAX_KEY_BYTES:
            raise ValueError("pseudonymization key length is out of bounds")
        return value


class SanitizationTransformResult(BaseModel):
    """Immutable, metadata-aware output of one value-level transform.

    ``dropped`` distinguishes a genuine ``None`` transform result from a dropped cell, so a
    legitimate null is never confused with a field that Phase 3E will omit. The payload ``value``
    is hidden from ``repr``; ``model_dump`` carries it because that is the transform payload.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    action: SanitizationAction
    value: SanitizedValue = Field(default=None, repr=False)
    dropped: bool
    transformer_version: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value_domain(cls, value: object) -> object:
        if value is None or type(value) in (bool, int, float, str):
            return value
        raise ValueError("transform value is outside the sanitized scalar domain")

    @model_validator(mode="after")
    def _validate_consistency(self) -> Self:
        if self.action is SanitizationAction.DROP:
            if self.dropped and self.value is None:
                return self
            raise ValueError("a dropped result must set dropped and carry no value")
        if self.dropped:
            raise ValueError("dropped must be false for non-drop actions")
        expected_marker = {
            SanitizationAction.REDACT: _REDACTED_MARKER,
            SanitizationAction.MASK: _MASKED_MARKER,
        }.get(self.action)
        if expected_marker is not None and self.value not in (None, expected_marker):
            raise ValueError("redact and mask results require their action's marker value")
        pseudonym_is_valid = self.value is None or (
            isinstance(self.value, str) and _PSEUDONYM_PATTERN.fullmatch(self.value) is not None
        )
        if self.action is SanitizationAction.PSEUDONYMIZE and not pseudonym_is_valid:
            raise ValueError("pseudonymize results require a versioned token value")
        if (
            self.action is SanitizationAction.ALLOW
            and isinstance(self.value, float)
            and not math.isfinite(self.value)
        ):
            raise ValueError("an allowed float must be finite")
        return self


@dataclass(slots=True)
class _Traversal:
    """Shared, per-value container budget and depth for one pseudonymization traversal."""

    config: SanitizationTransformConfig
    elements: int = 0

    def begin_container(self) -> None:
        """Count one container's elements against the shared per-value budget."""
        self.elements += 1
        if self.elements > self.config.max_container_elements:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)


def _tag(tag: int) -> bytes:
    return struct.pack("<B", tag)


def _framed(payload: bytes) -> bytes:
    return struct.pack("<Q", len(payload)) + payload


def _bounded_binary(value: bytes | bytearray | memoryview, *, limit: int) -> bytes:
    size = value.nbytes if type(value) is memoryview else len(value)
    if size > limit:
        raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
    return bytes(value)


def _canonical_scalar(  # noqa: PLR0911, PLR0912 - one explicit branch per supported scalar type.
    value: object,
    config: SanitizationTransformConfig,
) -> bytes:
    """Return the collision-safe canonical bytes for one supported scalar.

    The representation is explicit about type, so ``"1"``/``1``/``True``/``1.0`` never collide.
    No generic ``str()``/``repr()`` is called on the value.
    """
    if value is None:
        return _tag(_TAG_NULL)
    if value is True:
        return _tag(_TAG_TRUE)
    if value is False:
        return _tag(_TAG_FALSE)
    if type(value) is int:
        return _tag(_TAG_INT) + _framed(str(value).encode("ascii"))
    if type(value) is float:
        if not math.isfinite(value):
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return _tag(_TAG_FLOAT) + _framed(value.hex().encode("ascii"))
    if type(value) is str:
        if len(value) > config.max_text_chars:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return _tag(_TAG_STR) + _framed(value.encode("utf-8"))
    if type(value) is Decimal:
        if not math.isfinite(value):
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return _tag(_TAG_DECIMAL) + _framed(str(value).encode("ascii"))
    if type(value) is datetime:
        return _tag(_TAG_DATETIME) + _framed(value.isoformat().encode("utf-8"))
    if type(value) is date:
        return _tag(_TAG_DATE) + _framed(value.isoformat().encode("utf-8"))
    if type(value) is time:
        return _tag(_TAG_TIME) + _framed(value.isoformat().encode("utf-8"))
    if type(value) is UUID:
        return _tag(_TAG_UUID) + _framed(value.bytes)
    if type(value) in (bytes, bytearray, memoryview):
        raw = _bounded_binary(
            cast("bytes | bytearray | memoryview", value), limit=config.max_binary_bytes
        )
        return _tag(_TAG_BYTES) + _framed(raw)
    raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)


def _canonicalize(
    value: object,
    *,
    config: SanitizationTransformConfig,
    traversal: _Traversal,
    depth: int,
) -> bytes:
    if isinstance(value, list):
        if depth >= config.max_container_depth:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        payload = b"".join(
            _canonicalize_item(item, config=config, traversal=traversal, depth=depth + 1)
            for item in value
        )
        return _tag(_TAG_LIST) + _framed(payload)
    if isinstance(value, tuple):
        if depth >= config.max_container_depth:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        payload = b"".join(
            _canonicalize_item(item, config=config, traversal=traversal, depth=depth + 1)
            for item in value
        )
        return _tag(_TAG_TUPLE) + _framed(payload)
    if isinstance(value, Mapping):
        if depth >= config.max_container_depth:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        entries: list[tuple[str, object]] = []
        for key, item in value.items():
            traversal.begin_container()
            if type(key) is not str:
                raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
            entries.append((key, item))
        payload = b"".join(
            _canonical_mapping_entry(key, item, config=config, traversal=traversal, depth=depth)
            for key, item in sorted(entries)
        )
        return _tag(_TAG_MAPPING) + _framed(payload)
    return _canonical_scalar(value, config)


def _canonicalize_item(
    item: object,
    *,
    config: SanitizationTransformConfig,
    traversal: _Traversal,
    depth: int,
) -> bytes:
    traversal.begin_container()
    return _canonicalize(item, config=config, traversal=traversal, depth=depth)


def _canonical_mapping_entry(
    key: str,
    value: object,
    *,
    config: SanitizationTransformConfig,
    traversal: _Traversal,
    depth: int,
) -> bytes:
    return _canonical_scalar(key, config) + _canonicalize(
        value, config=config, traversal=traversal, depth=depth + 1
    )


def _canonicalize_bounded(value: object, config: SanitizationTransformConfig) -> bytes:
    traversal = _Traversal(config=config)
    return _canonicalize(value, config=config, traversal=traversal, depth=0)


def _pseudonymize(value: object, config: SanitizationTransformConfig) -> SanitizedValue:
    if value is None:
        return None
    key = config.pseudonymization_key
    if key is None:
        raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
    message = _DOMAIN_SEPARATOR + _canonicalize_bounded(value, config)
    digest = hmac.new(key.get_secret_value().encode("utf-8"), message, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{_PSEUDONYM_PREFIX}{encoded}"


def _normalize_allowed(  # noqa: PLR0911 - one explicit branch per supported scalar type.
    value: object, config: SanitizationTransformConfig
) -> SanitizedValue:
    if value is None or type(value) in (bool, int):
        return cast("SanitizedValue", value)
    if type(value) is float:
        if not math.isfinite(value):
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return value
    if type(value) is str:
        if len(value) > config.max_text_chars:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return value
    if type(value) is Decimal:
        if not math.isfinite(value):
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return str(value)
    if type(value) in (datetime, date, time):
        return cast("datetime | date | time", value).isoformat()
    if type(value) is UUID:
        return str(value)
    if type(value) in (bytes, bytearray, memoryview):
        raw = _bounded_binary(
            cast("bytes | bytearray | memoryview", value), limit=config.max_binary_bytes
        )
        text = raw.decode("utf-8", errors="strict")
        if len(text) > config.max_text_chars:
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)
        return text
    raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)


class SanitizationTransformer:
    """Apply one resolved ``SanitizationAction`` to one raw value.

    The transformer executes ``decision.action`` exactly. It performs no classification and does
    not re-run the policy. It bounds each value by its own ``SanitizationTransformConfig`` and
    never calls ``str()``/``repr()`` on an unsupported or arbitrary object.
    """

    def __init__(self, config: SanitizationTransformConfig | None = None) -> None:
        self.config = config if config is not None else SanitizationTransformConfig()

    def _apply(self, value: object, action: SanitizationAction) -> SanitizedValue:
        """Apply one non-drop action to ``value``, fail-closed on an unknown action."""
        match action:
            case SanitizationAction.REDACT:
                return None if value is None else _REDACTED_MARKER
            case SanitizationAction.MASK:
                return None if value is None else _MASKED_MARKER
            case SanitizationAction.ALLOW:
                return _normalize_allowed(value, self.config)
            case SanitizationAction.PSEUDONYMIZE:
                return _pseudonymize(value, self.config)
            case _:
                raise SanitizationTransformError(_SAFE_ERROR_MESSAGE)

    def _produce(self, value: object, action: SanitizationAction) -> SanitizedValue:
        """Apply one non-drop action, converting any failure to the safe public error."""
        try:
            return self._apply(value, action)
        except SanitizationTransformError:
            raise
        except Exception:  # noqa: BLE001 - raw driver objects must fail closed without leaking.
            raise SanitizationTransformError(_SAFE_ERROR_MESSAGE) from None

    def transform(
        self,
        value: object,
        decision: SanitizationDecision,
    ) -> SanitizationTransformResult:
        """Apply ``decision.action`` to ``value`` and return a safe, metadata-aware result."""
        if not isinstance(decision, SanitizationDecision):
            raise TypeError("decision must be a SanitizationDecision")
        action = decision.action
        if action is SanitizationAction.DROP:
            return SanitizationTransformResult(
                action=action, value=None, dropped=True, transformer_version=_TRANSFORMER_VERSION
            )
        return SanitizationTransformResult(
            action=action,
            value=self._produce(value, action),
            dropped=False,
            transformer_version=_TRANSFORMER_VERSION,
        )
