"""Deterministic, bounded PII detection for raw samples."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import date, datetime, time
from decimal import Decimal
from itertools import pairwise
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security.models import (
    FieldClassification,
    FieldReference,
    SensitivityClass,
)

_DETECTOR_VERSION = "pii.v1"
_SAFE_ERROR_MESSAGE = "PII detection could not complete safely"

_MAX_CELLS = 1_000_000
_MAX_TEXT_CHARS = 1_000_000
_MAX_BINARY_BYTES = 1_000_000
_MAX_CONTAINER_DEPTH = 32
_MAX_CONTAINER_ELEMENTS = 1_000_000
_MAX_TOTAL_CONTAINER_ELEMENTS = 10_000_000
_CARD_MIN_DIGITS = 13
_CARD_MAX_DIGITS = 19
_LUHN_CARRY = 9
_IBAN_MIN_LENGTH = 15
_IBAN_MAX_LENGTH = 34

_COLUMN_NAME = "pii.column_name"
_NESTED_KEY = "pii.nested_key"
_EMAIL = "pii.email"
_PHONE = "pii.phone"
_IP = "pii.ip"
_MAC = "pii.mac"
_PAYMENT_CARD = "pii.payment_card"
_IBAN = "pii.iban"
_UNINSPECTABLE = "pii.uninspectable"

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NAME_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_EMAIL_VALUE_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)
_INTL_PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_IBAN_SHAPE_RE = re.compile(r"^[A-Z]{2}[0-9]{2}[0-9A-Z]{11,30}$", re.ASCII)

# Curated, conservative name tokens for PII classification. Bare ambiguous tokens
# (name, id, number, address) are matched only in the person/entity contexts below.
_SINGLE_TOKENS = frozenset(
    {
        # email
        "email",
        # phone
        "phone",
        "telephone",
        "cell",
        # person name
        "firstname",
        "lastname",
        "surname",
        "fullname",
        # birth date
        "dob",
        "birthday",
        # postal address
        "address",
        "postcode",
        # personal identifiers
        "ssn",
        "nationalid",
        "passportnumber",
        # financial identifiers
        "iban",
        # IP / MAC
        "ipaddress",
        "ipv4",
        "ipv6",
        "mac",
    }
)
_TOKEN_PAIRS = frozenset(
    {
        # email
        ("email", "address"),
        ("e", "mail"),
        # phone
        ("phone", "number"),
        ("telephone", "number"),
        ("mobile", "number"),
        # person name (person/entity context only)
        ("first", "name"),
        ("last", "name"),
        ("full", "name"),
        ("given", "name"),
        ("user", "name"),
        ("person", "name"),
        ("legal", "name"),
        ("customer", "name"),
        ("contact", "name"),
        ("patient", "name"),
        ("employee", "name"),
        ("guardian", "name"),
        ("parent", "name"),
        ("staff", "name"),
        # birth date
        ("birth", "date"),
        ("date", "birth"),
        ("of", "birth"),
        ("birth", "year"),
        # postal address
        ("postal", "address"),
        ("home", "address"),
        ("street", "address"),
        ("shipping", "address"),
        ("mailing", "address"),
        ("postal", "code"),
        ("zip", "code"),
        # personal identifiers (curated person/entity contexts, not any (x, id))
        ("user", "id"),
        ("customer", "id"),
        ("patient", "id"),
        ("employee", "id"),
        ("member", "id"),
        ("person", "id"),
        ("contact", "id"),
        ("citizen", "id"),
        ("driver", "id"),
        ("national", "id"),
        ("passport", "number"),
        ("passport", "id"),
        ("driver", "license"),
        # financial identifiers
        ("card", "number"),
        ("bank", "account"),
        # IP / MAC metadata
        ("ip", "address"),
        ("mac", "address"),
    }
)

_SENSITIVITY_RANK = {
    SensitivityClass.UNKNOWN: 1,
    SensitivityClass.PII: 2,
}
_DETECTOR_RANK = {
    _UNINSPECTABLE: 0,
    _COLUMN_NAME: 1,
    _NESTED_KEY: 2,
    _EMAIL: 3,
    _PHONE: 4,
    _IP: 5,
    _MAC: 6,
    _PAYMENT_CARD: 7,
    _IBAN: 8,
}


class PIIDetectionError(RuntimeError):
    """Safe public failure raised when bounded PII detection cannot complete."""


class PIIDetectionConfig(BaseModel):
    """Immutable resource limits for PII scanning."""

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


class PIIDetectionResult(BaseModel):
    """Safe metadata-only findings from one bounded raw sample scan."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    detector_version: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    classifications: tuple[FieldClassification, ...]
    scanned_fields: int = Field(ge=0, strict=True)
    scanned_rows: int = Field(ge=0, strict=True)
    scanned_cells: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def validate_safe_metadata(self) -> PIIDetectionResult:
        if self.scanned_cells != self.scanned_fields * self.scanned_rows:
            raise ValueError("pii detection result counts are inconsistent")
        if any(
            finding.sensitivity not in (SensitivityClass.PII, SensitivityClass.UNKNOWN)
            for finding in self.classifications
        ):
            raise ValueError("pii detection result contains an unsupported sensitivity")
        fields = tuple(finding.field for finding in self.classifications)
        if len(set(fields)) != len(fields) or len(fields) > self.scanned_fields:
            raise ValueError("pii detection result contains duplicate or excess fields")
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
class PIIDetector:
    """Scan raw database samples for PII without retaining or returning their values."""

    config: PIIDetectionConfig = dataclass_field(default_factory=PIIDetectionConfig)

    def detect(self, sample: SampleResult) -> PIIDetectionResult:
        """Return at most one metadata-only finding per source column."""
        if not isinstance(sample, SampleResult):
            raise TypeError("sample must be a SampleResult")

        scanned_fields = len(sample.columns)
        scanned_cells = sample.row_count * scanned_fields
        if scanned_cells > self.config.max_cells:
            raise PIIDetectionError(_SAFE_ERROR_MESSAGE)

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
            raise PIIDetectionError(_SAFE_ERROR_MESSAGE) from None

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
                except PIIDetectionError:
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

        return PIIDetectionResult(
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
        if any(token in _SINGLE_TOKENS for token in tokens) or bool(pairs & _TOKEN_PAIRS):
            return _Signal(SensitivityClass.PII, 0.9, detector)
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
            raise PIIDetectionError(_SAFE_ERROR_MESSAGE)
        return state.elements <= self.config.max_container_elements


def _inspect_text(value: str) -> _Signal | None:
    text = value.strip()
    checks = (
        (_is_email, _EMAIL, 0.99),
        (_has_international_phone, _PHONE, 0.99),
        (_is_ip_address, _IP, 0.98),
        (_is_mac, _MAC, 0.98),
        (_is_payment_card, _PAYMENT_CARD, 0.99),
        (_is_iban, _IBAN, 0.99),
    )
    for check, detector, confidence in checks:
        if check(text):
            return _Signal(SensitivityClass.PII, confidence, detector)
    return None


def _is_email(text: str) -> bool:
    return _EMAIL_VALUE_RE.fullmatch(text) is not None


def _is_mac(text: str) -> bool:
    return _MAC_RE.fullmatch(text) is not None


def _has_international_phone(text: str) -> bool:
    if not text.startswith("+"):
        return False
    digits = re.sub(r"[\s\-().]", "", text)
    return _INTL_PHONE_RE.fullmatch(digits) is not None


def _is_ip_address(text: str) -> bool:
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_payment_card(text: str) -> bool:
    digits = re.sub(r"[\s-]", "", text)
    if not digits.isdigit() or not _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS:
        return False
    return _luhn_valid(digits)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, ch in enumerate(reversed(digits)):
        value = int(ch)
        if index % 2 == 1:
            value *= 2
            if value > _LUHN_CARRY:
                value -= _LUHN_CARRY
        total += value
    return total % 10 == 0


def _is_iban(text: str) -> bool:
    iban = text.strip().upper()
    if not _IBAN_MIN_LENGTH <= len(iban) <= _IBAN_MAX_LENGTH or not _IBAN_SHAPE_RE.fullmatch(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    if not rearranged.isalnum():
        return False
    number = "".join(
        str(ord(character) - 55) if character.isalpha() else character for character in rearranged
    )
    return int(number) % 97 == 1


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
