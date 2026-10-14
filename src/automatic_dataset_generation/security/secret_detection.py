"""Deterministic, bounded secret and credential detection for raw samples."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import date, datetime, time
from decimal import Decimal
from itertools import pairwise
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security.models import (
    FieldClassification,
    FieldReference,
    SensitivityClass,
)

_DETECTOR_VERSION = "secret_credential.v1"
_SAFE_ERROR_MESSAGE = "Secret and credential detection could not complete safely"

_MAX_CELLS = 1_000_000
_MAX_TEXT_CHARS = 1_000_000
_MAX_BINARY_BYTES = 1_000_000
_MAX_CONTAINER_DEPTH = 32
_MAX_CONTAINER_ELEMENTS = 1_000_000
_MAX_TOTAL_CONTAINER_ELEMENTS = 10_000_000

_COLUMN_NAME = "secret_credential.column_name"
_NESTED_KEY = "secret_credential.nested_key"
_PRIVATE_KEY = "secret_credential.private_key"  # pragma: allowlist secret
_AUTH_HEADER = "secret_credential.auth_header"
_JWT = "secret_credential.jwt"
_URI_USERINFO = "secret_credential.uri_userinfo"
_KEY_VALUE = "secret_credential.key_value"
_UNINSPECTABLE = "secret_credential.uninspectable"

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NAME_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_AUTH_HEADER_RE = re.compile(
    r"^\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{4,}\s*$",
    re.IGNORECASE,
)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{16,}$")
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?:^|[\s{,;&?])"
    r"[\"']?(?:password|passwd|pwd|passphrase|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"client[_-]?secret|credentials?|connection[_-]?string)[\"']?"
    r"\s*(?:=|:)\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,;&}{]+)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?:^|[\s{,;&?])[\"']?(?:secret|private[_-]?key|secret[_-]?key|"
    r"signing[_-]?key|encryption[_-]?key)[\"']?"
    r"\s*(?:=|:)\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,;&}{]+)",
    re.IGNORECASE,
)

_CREDENTIAL_SINGLE_TOKENS = frozenset(
    {"password", "passwd", "pwd", "passphrase", "apikey", "token", "credential", "credentials"}
)
_CREDENTIAL_TOKEN_PAIRS = frozenset(
    {
        ("api", "key"),
        ("access", "token"),
        ("refresh", "token"),
        ("auth", "token"),
        ("bearer", "token"),
        ("client", "secret"),
        ("connection", "string"),
    }
)
_SECRET_TOKEN_PAIRS = frozenset(
    {
        ("private", "key"),
        ("secret", "key"),
        ("signing", "key"),
        ("encryption", "key"),
    }
)

_SENSITIVITY_RANK = {
    SensitivityClass.UNKNOWN: 1,
    SensitivityClass.SECRET: 2,
    SensitivityClass.CREDENTIAL: 3,
}
_DETECTOR_RANK = {
    _UNINSPECTABLE: 0,
    _COLUMN_NAME: 1,
    _NESTED_KEY: 2,
    _KEY_VALUE: 3,
    _PRIVATE_KEY: 4,
    _URI_USERINFO: 5,
    _JWT: 6,
    _AUTH_HEADER: 7,
}


class SecretDetectionError(RuntimeError):
    """Safe public failure raised when bounded detection cannot complete."""


class SecretDetectionConfig(BaseModel):
    """Immutable resource limits for secret and credential scanning."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    max_cells: int = Field(default=10_000, gt=0, le=_MAX_CELLS, strict=True)
    max_text_chars: int = Field(default=16_384, gt=0, le=_MAX_TEXT_CHARS, strict=True)
    max_binary_bytes: int = Field(default=16_384, gt=0, le=_MAX_BINARY_BYTES, strict=True)
    max_container_depth: int = Field(default=8, gt=0, le=_MAX_CONTAINER_DEPTH, strict=True)
    max_container_elements: int = Field(
        default=10_000,
        gt=0,
        le=_MAX_CONTAINER_ELEMENTS,
        strict=True,
    )
    max_total_container_elements: int = Field(
        default=100_000,
        gt=0,
        le=_MAX_TOTAL_CONTAINER_ELEMENTS,
        strict=True,
    )


class SecretDetectionResult(BaseModel):
    """Safe metadata-only findings from one bounded raw sample scan."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    detector_version: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    classifications: tuple[FieldClassification, ...]
    scanned_fields: int = Field(ge=0, strict=True)
    scanned_rows: int = Field(ge=0, strict=True)
    scanned_cells: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def validate_safe_metadata(self) -> SecretDetectionResult:
        if self.scanned_cells != self.scanned_fields * self.scanned_rows:
            raise ValueError("secret detection result counts are inconsistent")
        if any(
            finding.sensitivity
            not in (SensitivityClass.CREDENTIAL, SensitivityClass.SECRET, SensitivityClass.UNKNOWN)
            for finding in self.classifications
        ):
            raise ValueError("secret detection result contains an unsupported sensitivity")
        fields = tuple(finding.field for finding in self.classifications)
        if len(set(fields)) != len(fields) or len(fields) > self.scanned_fields:
            raise ValueError("secret detection result contains duplicate or excess fields")
        return self


@dataclass(frozen=True, slots=True)
class _Signal:
    sensitivity: SensitivityClass
    confidence: float
    detector: str


@dataclass(slots=True)
class _DetectionState:
    container_elements: int = 0


@dataclass(slots=True)
class _ContainerState:
    detection: _DetectionState
    elements: int = 0


_UNKNOWN_SIGNAL = _Signal(SensitivityClass.UNKNOWN, 0.0, _UNINSPECTABLE)


@dataclass(frozen=True, slots=True)
class SecretCredentialDetector:
    """Scan raw database samples without retaining or returning their values."""

    config: SecretDetectionConfig = dataclass_field(default_factory=SecretDetectionConfig)

    def detect(self, sample: SampleResult) -> SecretDetectionResult:
        """Return at most one metadata-only finding per source column."""
        if not isinstance(sample, SampleResult):
            raise TypeError("sample must be a SampleResult")

        scanned_fields = len(sample.columns)
        scanned_cells = sample.row_count * scanned_fields
        if scanned_cells > self.config.max_cells:
            raise SecretDetectionError(_SAFE_ERROR_MESSAGE)

        try:
            field_references = tuple(
                FieldReference(
                    schema_name=sample.schema_name,
                    table_name=sample.table_name,
                    column_name=column,
                )
                for column in sample.columns
            )
        except ValidationError:
            raise SecretDetectionError(_SAFE_ERROR_MESSAGE) from None

        classifications: list[FieldClassification] = []
        detection_state = _DetectionState()
        for column_index, (column, field_reference) in enumerate(
            zip(sample.columns, field_references, strict=True)
        ):
            signal = self._inspect_name(column, detector=_COLUMN_NAME)
            for row in sample.rows:
                try:
                    value_signal = self._inspect_value(
                        row[column_index],
                        state=_ContainerState(detection=detection_state),
                        depth=0,
                    )
                except SecretDetectionError:
                    raise
                except Exception:  # noqa: BLE001 - raw driver objects must fail closed safely.
                    value_signal = _UNKNOWN_SIGNAL
                signal = _stronger_signal(signal, value_signal)

            if signal is not None:
                classifications.append(
                    FieldClassification(
                        field=field_reference,
                        sensitivity=signal.sensitivity,
                        confidence=signal.confidence,
                        detector=signal.detector,
                    )
                )

        return SecretDetectionResult(
            detector_version=_DETECTOR_VERSION,
            classifications=tuple(classifications),
            scanned_fields=scanned_fields,
            scanned_rows=sample.row_count,
            scanned_cells=scanned_cells,
        )

    def _inspect_name(self, name: str, *, detector: str) -> _Signal | None:
        if len(name) > self.config.max_text_chars:
            return _UNKNOWN_SIGNAL
        separated = _CAMEL_BOUNDARY_RE.sub("_", name)
        tokens = tuple(token.lower() for token in _NAME_TOKEN_RE.findall(separated))
        pairs = frozenset(pairwise(tokens))
        if any(token in _CREDENTIAL_SINGLE_TOKENS for token in tokens) or bool(
            pairs & _CREDENTIAL_TOKEN_PAIRS
        ):
            return _Signal(SensitivityClass.CREDENTIAL, 0.9, detector)
        if "secret" in tokens or bool(pairs & _SECRET_TOKEN_PAIRS):
            return _Signal(SensitivityClass.SECRET, 0.9, detector)
        return None

    def _inspect_value(
        self,
        value: object,
        *,
        state: _ContainerState,
        depth: int,
    ) -> _Signal | None:
        signal: _Signal | None = None
        if value is None or type(value) in (bool, int, float):
            pass
        elif type(value) is str:
            signal = (
                _UNKNOWN_SIGNAL if len(value) > self.config.max_text_chars else _inspect_text(value)
            )
        elif isinstance(value, (bytes, bytearray, memoryview)):
            signal = self._inspect_binary(value)
        elif isinstance(value, Mapping):
            signal = self._inspect_mapping(value, state=state, depth=depth)
        elif isinstance(value, (list, tuple)):
            signal = self._inspect_sequence(value, state=state, depth=depth)
        elif not isinstance(value, (Decimal, datetime, date, time, UUID)):
            signal = _UNKNOWN_SIGNAL
        return signal

    def _inspect_binary(self, value: bytes | bytearray | memoryview) -> _Signal | None:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > self.config.max_binary_bytes:
            return _UNKNOWN_SIGNAL
        try:
            text = bytes(value).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return _UNKNOWN_SIGNAL
        if len(text) > self.config.max_text_chars:
            return _UNKNOWN_SIGNAL
        return _inspect_text(text)

    def _inspect_sequence(
        self,
        value: list[object] | tuple[object, ...],
        *,
        state: _ContainerState,
        depth: int,
    ) -> _Signal | None:
        if depth >= self.config.max_container_depth:
            return _UNKNOWN_SIGNAL
        signal: _Signal | None = None
        for item in value:
            if not self._consume_container_element(state):
                return _stronger_signal(signal, _UNKNOWN_SIGNAL)
            signal = _stronger_signal(
                signal,
                self._inspect_value(item, state=state, depth=depth + 1),
            )
        return signal

    def _inspect_mapping(
        self,
        value: Mapping[object, object],
        *,
        state: _ContainerState,
        depth: int,
    ) -> _Signal | None:
        if depth >= self.config.max_container_depth:
            return _UNKNOWN_SIGNAL
        signal: _Signal | None = None
        for key, item in value.items():
            if not self._consume_container_element(state):
                return _stronger_signal(signal, _UNKNOWN_SIGNAL)
            if isinstance(key, str):
                signal = _stronger_signal(
                    signal,
                    self._inspect_name(key, detector=_NESTED_KEY),
                )
            else:
                signal = _stronger_signal(signal, _UNKNOWN_SIGNAL)
            signal = _stronger_signal(
                signal,
                self._inspect_value(item, state=state, depth=depth + 1),
            )
        return signal

    def _consume_container_element(self, state: _ContainerState) -> bool:
        state.elements += 1
        state.detection.container_elements += 1
        if state.detection.container_elements > self.config.max_total_container_elements:
            raise SecretDetectionError(_SAFE_ERROR_MESSAGE)
        return state.elements <= self.config.max_container_elements


def _inspect_text(value: str) -> _Signal | None:
    signal: _Signal | None = None
    if _AUTH_HEADER_RE.fullmatch(value):
        signal = _Signal(SensitivityClass.CREDENTIAL, 0.99, _AUTH_HEADER)
    elif _JWT_RE.fullmatch(value):
        signal = _Signal(SensitivityClass.CREDENTIAL, 0.99, _JWT)
    elif _has_uri_password(value):
        signal = _Signal(SensitivityClass.CREDENTIAL, 0.99, _URI_USERINFO)
    elif _CREDENTIAL_ASSIGNMENT_RE.search(value):
        signal = _Signal(SensitivityClass.CREDENTIAL, 0.98, _KEY_VALUE)
    elif _PRIVATE_KEY_RE.search(value):
        signal = _Signal(SensitivityClass.SECRET, 0.99, _PRIVATE_KEY)
    elif _SECRET_ASSIGNMENT_RE.search(value):
        signal = _Signal(SensitivityClass.SECRET, 0.98, _KEY_VALUE)
    return signal


def _has_uri_password(value: str) -> bool:
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme and parsed.hostname and parsed.username and parsed.password)
    except ValueError:
        return False


def _stronger_signal(current: _Signal | None, candidate: _Signal | None) -> _Signal | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    current_key = (
        _SENSITIVITY_RANK[current.sensitivity],
        current.confidence,
        _DETECTOR_RANK[current.detector],
    )
    candidate_key = (
        _SENSITIVITY_RANK[candidate.sensitivity],
        candidate.confidence,
        _DETECTOR_RANK[candidate.detector],
    )
    return candidate if candidate_key > current_key else current
