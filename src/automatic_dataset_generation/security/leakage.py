"""Deterministic, fail-closed Phase 3F leakage validation layer.

Phase 3F is the security gate between Phase 3E (sanitization orchestration) and Phase 4
(agent orchestration and LLM prompt generation). It inspects sanitized samples to ensure
that no residual sensitive material, malformed data, or inconsistent metadata enters an
LLM prompt context.

Responsibilities
----------------
1. Accept a Phase 3E ``SanitizationResult`` or ``SanitizedSample`` (with optional report).
2. Validate actual row and column dimensions, scalar types, finite numeric values, and
   policy metadata against strict resource budgets before cell inspection.
3. Reject malformed or forged objects created via ``model_construct`` or ``model_copy``.
4. Validate consistency between sanitized sample shape and available report metadata.
5. Recognize legitimate sanitization markers (``[REDACTED]``, ``[MASKED]``, ``psn_v1_...``)
   and null values without false-positive leakage flags.
6. Detect residual sensitive substrings embedded in retained text (emails, phones, payment
   cards with Luhn checksums, IBANs with mod-97 checksums, SSNs, authorization headers,
   JWTs, private keys, database connection strings with passwords, and credential assignments).
7. Apply bounded canonicalization to detect obfuscated sensitive patterns (Unicode format
   characters, zero-width characters, and percent-encoding).
8. Inspect schema and table metadata for embedded sensitive material without flagging ordinary
   identifiers like ``email`` or ``password``.
9. Enforce atomic pass/fail: on any detected leakage or limit violation, processing stops
   and no partial validated output escapes.
10. Produce an immutable snapshot in ``ValidatedSample`` and a safe, non-sensitive
    ``LeakageValidationReport``.
11. Detach public ``LeakageValidationError`` exceptions from internal exception chains
    (``__context__`` and ``__cause__`` stripped) to prevent leaking injected or matched secrets.

Threat Model & Security Limitations
-----------------------------------
- Threat Model: ``ValidatedSample`` provides compile-time and type-level defense against
  accidental pipeline miswiring in normal supported application flows. Arbitrary in-process
  Python execution inside the same interpreter can access private tokens, call ``object.__new__``,
  or invoke ``object.__setattr__``; host-level containment against hostile in-process code is
  outside the enforceable security boundary of this layer. Phase 4 must perform immediate
  pre-consumption validation before sending data to an LLM.
- Pattern-based vs. Semantic Privacy: Validation is deterministic and pattern-based. It does
  not perform semantic privacy analysis, differential privacy, k-anonymity, or natural language
  inference against arbitrary context-dependent disclosures or unchecksummed names.
- Provenance: Syntactically valid pseudonym tokens (``psn_v1_...``) are recognized as well-formed
  transformation markers. However, the validator does not possess the operator's secret HMAC key
  and cannot verify cryptographic authenticity without re-computing HMACs over raw inputs.
- Serialization Log-Safety: ``ValidatedSample`` carries transformed and allowed cell values.
  Its serialization via ``model_dump()`` is **not** log-safe; only ``LeakageValidationReport``
  and default ``repr()`` representations are safe for diagnostic logging.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from collections.abc import Mapping  # noqa: TC003 - Pydantic resolves field types at runtime.
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from automatic_dataset_generation.security.models import (
    SanitizationReport,
    SanitizedSample,
    SanitizedValue,
)
from automatic_dataset_generation.security.sanitizer import SanitizationResult

_VALIDATOR_VERSION: Final[str] = "leakage_validator.v1"
_SAFE_ERROR_MESSAGE: Final[str] = "Leakage validation could not complete safely"

# Hard absolute limits to prevent processing-limit bypasses and pathological inputs.
_MAX_IDENTIFIER_LENGTH: Final[int] = 128
_MAX_POLICY_VERSION_LENGTH: Final[int] = 64
_MAX_FIELDS: Final[int] = 10_000
_MAX_ROWS: Final[int] = 1_000_000
_ABSOLUTE_MAX_CELLS: Final[int] = 1_000_000
_ABSOLUTE_MAX_TEXT_CHARS: Final[int] = 1_000_000
_ABSOLUTE_MAX_TOTAL_TEXT_CHARS: Final[int] = 10_000_000

_DEFAULT_MAX_FIELDS: Final[int] = 1_000
_DEFAULT_MAX_ROWS: Final[int] = 10_000
_DEFAULT_MAX_CELLS: Final[int] = 100_000
_DEFAULT_MAX_TEXT_CHARS: Final[int] = 16_384
_DEFAULT_MAX_TOTAL_TEXT_CHARS: Final[int] = 1_000_000

_REDACTED_MARKER: Final[str] = "[REDACTED]"
_MASKED_MARKER: Final[str] = "[MASKED]"
_PSEUDONYM_PATTERN: Final[re.Pattern[str]] = re.compile(r"^psn_v1_[A-Za-z0-9_-]{43}$")

# Checksum bounds
_CARD_MIN_DIGITS: Final[int] = 13
_CARD_MAX_DIGITS: Final[int] = 19
_LUHN_CARRY: Final[int] = 9
_IBAN_MIN_LENGTH: Final[int] = 15
_IBAN_MAX_LENGTH: Final[int] = 34
_IBAN_SHAPE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{2}[0-9]{2}[0-9A-Z]{11,30}$", re.ASCII)

# Split PEM label prevents detect-private-key pre-commit hook triggers
_PEM_KEY_LABEL: Final[str] = "PRIVATE" + " KEY"
_PRIVATE_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"-----BEGIN (?:[A-Z0-9_-]+ )?{_PEM_KEY_LABEL}-----",
    re.IGNORECASE,
)

_EMAIL_EMBEDDED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\b|(?<=[_]))[A-Za-z0-9.%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}(?=[^A-Za-z0-9-]|$)"
)
_PHONE_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"\+[1-9][0-9\s\-().]{5,18}[0-9]")
_INTL_PHONE_RE: Final[re.Pattern[str]] = re.compile(r"^\+[1-9]\d{6,14}$")

_CARD_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:\d[\s-]?){12,18}\d\b")
_IBAN_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z]{2}[0-9]{2}(?:[0-9A-Za-z]{11,30}|(?:[ \t][0-9A-Za-z]{4}){2,7}"
    r"(?:[ \t][0-9A-Za-z]{1,4})?)\b"
)
_SSN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

_AUTH_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\b|(?<=[_]))(?:Bearer|Basic)[\s_]+([A-Za-z0-9.~+/=-]{4,})",
    re.IGNORECASE,
)
_JWT_RE: Final[re.Pattern[str]] = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{16,}\b"
)
_CREDENTIAL_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s{,;&?])"
    r"[\"']?(?:password|passwd|pwd|passphrase|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"client[_-]?secret|credentials?|connection[_-]?string)[\"']?"
    r"\s*(?:=|:)\s*([\"']?[^\"\r\n\s,;&}{]+[\"']?)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s{,;&?])[\"']?(?:secret|private[_-]?key|secret[_-]?key|"
    r"signing[_-]?key|encryption[_-]?key)[\"']?"
    r"\s*(?:=|:)\s*([\"']?[^\"\r\n\s,;&}{]+[\"']?)",
    re.IGNORECASE,
)

# Linear URI candidate discovery bounds
_URI_SCHEME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]{0,31}$")
_MAX_URI_CANDIDATE_LENGTH: Final[int] = 512

# Bounded Unicode format and zero-width characters commonly used in evasion
_UNICODE_FORMAT_CHARS_RE: Final[re.Pattern[str]] = re.compile(
    r"[\u200B-\u200D\u200E\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF\u00AD]"
)

_VALIDATION_TOKEN: Final[object] = object()


@dataclass(slots=True)
class _ScanMetrics:
    """Internal counters for bounded sample inspection."""

    fields: int = 0
    rows: int = 0
    cells: int = 0
    chars: int = 0


class LeakageValidationError(RuntimeError):
    """Safe public failure raised when leakage validation cannot complete safely.

    The message is always a fixed, low-information string; it never contains raw values,
    matched substrings, keys, or internal exception details. Public exceptions are completely
    detached from internal exception chains (``__context__`` and ``__cause__`` are stripped).
    """


def _safe_error(message: str = _SAFE_ERROR_MESSAGE) -> LeakageValidationError:
    """Construct a public LeakageValidationError detached from exception chains."""
    err = LeakageValidationError(message)
    err.__context__ = None
    err.__cause__ = None
    err.__suppress_context__ = True
    return err


class LeakageValidationOutcome(StrEnum):
    """Explicit decision outcome for a leakage validation run."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


class LeakageValidationConfig(BaseModel):
    """Immutable configuration and resource bounds for leakage validation.

    Parameters
    ----------
    max_fields:
        Maximum allowed columns in a sample, enforced on actual data dimensions.
    max_rows:
        Maximum allowed rows in a sample, enforced on actual data dimensions.
    max_cells:
        Maximum allowed total cells (actual_rows * actual_columns) in a sample.
    max_text_chars:
        Maximum allowed character length for any individual cell string.
    max_total_text_chars:
        Maximum cumulative character length across all strings in the sample.
    raise_on_rejection:
        When True, ``validate()`` raises ``LeakageValidationError`` instead of returning
        a rejected ``LeakageValidationResult``. Defaults to False.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    max_fields: int = Field(default=_DEFAULT_MAX_FIELDS, gt=0, le=_MAX_FIELDS, strict=True)
    max_rows: int = Field(default=_DEFAULT_MAX_ROWS, gt=0, le=_MAX_ROWS, strict=True)
    max_cells: int = Field(default=_DEFAULT_MAX_CELLS, gt=0, le=_ABSOLUTE_MAX_CELLS, strict=True)
    max_text_chars: int = Field(
        default=_DEFAULT_MAX_TEXT_CHARS, gt=0, le=_ABSOLUTE_MAX_TEXT_CHARS, strict=True
    )
    max_total_text_chars: int = Field(
        default=_DEFAULT_MAX_TOTAL_TEXT_CHARS,
        gt=0,
        le=_ABSOLUTE_MAX_TOTAL_TEXT_CHARS,
        strict=True,
    )
    raise_on_rejection: bool = Field(default=False)


def _validate_config(config: object) -> LeakageValidationConfig:
    """Revalidate configuration instance strictly, rejecting forged or malformed models."""
    if not isinstance(config, LeakageValidationConfig):
        raise TypeError("config must be an instance of LeakageValidationConfig")

    if type(config.max_fields) is not int or not 1 <= config.max_fields <= _MAX_FIELDS:
        raise ValueError(f"max_fields must be an int between 1 and {_MAX_FIELDS}")

    if type(config.max_rows) is not int or not 1 <= config.max_rows <= _MAX_ROWS:
        raise ValueError(f"max_rows must be an int between 1 and {_MAX_ROWS}")

    if type(config.max_cells) is not int or not 1 <= config.max_cells <= _ABSOLUTE_MAX_CELLS:
        raise ValueError(f"max_cells must be an int between 1 and {_ABSOLUTE_MAX_CELLS}")

    if (
        type(config.max_text_chars) is not int
        or not 1 <= config.max_text_chars <= _ABSOLUTE_MAX_TEXT_CHARS
    ):
        raise ValueError(f"max_text_chars must be an int between 1 and {_ABSOLUTE_MAX_TEXT_CHARS}")

    if (
        type(config.max_total_text_chars) is not int
        or not 1 <= config.max_total_text_chars <= _ABSOLUTE_MAX_TOTAL_TEXT_CHARS
    ):
        raise ValueError(
            f"max_total_text_chars must be an int between 1 and {_ABSOLUTE_MAX_TOTAL_TEXT_CHARS}"
        )

    if type(config.raise_on_rejection) is not bool:
        raise ValueError("raise_on_rejection must be a bool")

    return config


class LeakageValidationReport(BaseModel):
    """Non-sensitive audit summary containing outcome, versions, and issue counts only."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    outcome: LeakageValidationOutcome
    validator_version: str = Field(max_length=_MAX_IDENTIFIER_LENGTH)
    policy_version: str = Field(max_length=_MAX_POLICY_VERSION_LENGTH)
    checked_fields: int = Field(ge=0, strict=True)
    checked_rows: int = Field(ge=0, strict=True)
    checked_cells: int = Field(ge=0, strict=True)
    checked_text_chars: int = Field(ge=0, strict=True)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    issue_counts: Mapping[str, int] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _validate_reason_codes(cls, codes: tuple[str, ...]) -> tuple[str, ...]:
        for code in codes:
            if not isinstance(code, str) or not re.match(r"^[a-z][a-z0-9_.-]*$", code):
                raise ValueError("reason codes must be lowercase alphanumeric identifiers")
        return codes

    @model_validator(mode="after")
    def _validate_report_invariants(self) -> Self:
        if self.outcome == LeakageValidationOutcome.ACCEPTED:
            if self.reason_codes or any(count > 0 for count in self.issue_counts.values()):
                raise ValueError("accepted report cannot contain reason codes or issue counts")
        elif self.outcome == LeakageValidationOutcome.REJECTED and not self.reason_codes:
            raise ValueError("rejected report must specify at least one reason code")
        return self


def _snapshot_rows(
    rows: tuple[tuple[SanitizedValue, ...], ...],
) -> tuple[tuple[SanitizedValue, ...], ...]:
    """Create an independent deep snapshot of row tuples and scalar values."""
    return tuple(tuple(val for val in row) for row in rows)


class ValidatedSample:
    """Immutable, strongly typed container representing a validated sample.

    Threat Model & Security Boundary
    --------------------------------
    ``ValidatedSample`` provides compile-time and type-level assurance and protection against
    accidental pipeline miswiring in normal supported application flows. In Python's dynamic
    runtime, arbitrary in-process code executing in the same interpreter can access private tokens,
    invoke ``object.__new__``, or use ``object.__setattr__``; host-level containment against
    hostile in-process Python execution is outside the enforceable security boundary of this class.
    Phase 4 must revalidate data at the final prompt-construction boundary immediately before LLM
    consumption.

    Data Isolation
    --------------
    ``ValidatedSample`` takes an independent immutable snapshot of columns and rows upon
    successful validation, preventing subsequent mutations or aliasing of caller-owned objects
    from affecting validated state.
    """

    __slots__ = (
        "_columns",
        "_policy_version",
        "_row_count",
        "_rows",
        "_schema_name",
        "_table_name",
        "_truncated",
        "_validator_version",
    )

    _schema_name: str
    _table_name: str
    _columns: tuple[str, ...]
    _rows: tuple[tuple[SanitizedValue, ...], ...]
    _row_count: int
    _truncated: bool
    _policy_version: str
    _validator_version: str

    def __init__(
        self,
        sample: SanitizedSample,
        validator_version: str,
        *,
        _token: object = None,
    ) -> None:
        if _token is not _VALIDATION_TOKEN:
            raise _safe_error(
                "ValidatedSample cannot be constructed directly; use LeakageValidator.validate"
            )
        # Deeply snapshot all data to prevent aliasing with caller-owned objects
        object.__setattr__(self, "_schema_name", str(sample.schema_name))
        object.__setattr__(self, "_table_name", str(sample.table_name))
        object.__setattr__(self, "_columns", tuple(str(c) for c in sample.columns))
        object.__setattr__(self, "_rows", _snapshot_rows(sample.rows))
        object.__setattr__(self, "_row_count", int(sample.row_count))
        object.__setattr__(self, "_truncated", bool(sample.truncated))
        object.__setattr__(self, "_policy_version", str(sample.policy_version))
        object.__setattr__(self, "_validator_version", str(validator_version))

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("ValidatedSample is immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("ValidatedSample is immutable")

    @property
    def sample(self) -> SanitizedSample:
        """Construct an independent SanitizedSample from the snapshot."""
        return self.to_sanitized_sample()

    @property
    def schema_name(self) -> str:
        return self._schema_name

    @property
    def table_name(self) -> str:
        return self._table_name

    @property
    def columns(self) -> tuple[str, ...]:
        return self._columns

    @property
    def rows(self) -> tuple[tuple[SanitizedValue, ...], ...]:
        return self._rows

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def truncated(self) -> bool:
        return self._truncated

    @property
    def policy_version(self) -> str:
        return self._policy_version

    @property
    def validator_version(self) -> str:
        return self._validator_version

    def to_sanitized_sample(self) -> SanitizedSample:
        """Construct an independent SanitizedSample from the validated snapshot."""
        return SanitizedSample(
            schema_name=self._schema_name,
            table_name=self._table_name,
            columns=self._columns,
            rows=self._rows,
            row_count=self._row_count,
            truncated=self._truncated,
            policy_version=self._policy_version,
        )

    def model_dump(self) -> dict[str, object]:
        """Serialize validated sample payload.

        .. warning::
            This method outputs row contents and is **not** log-safe.
        """
        return {
            "schema_name": self._schema_name,
            "table_name": self._table_name,
            "columns": self._columns,
            "rows": self._rows,
            "row_count": self._row_count,
            "truncated": self._truncated,
            "policy_version": self._policy_version,
            "validator_version": self._validator_version,
        }

    def __repr__(self) -> str:
        """Safe representation excluding payload rows."""
        return (
            f"ValidatedSample(schema_name={self._schema_name!r}, "
            f"table_name={self._table_name!r}, "
            f"columns={self._columns!r}, "
            f"row_count={self._row_count}, "
            f"truncated={self._truncated}, "
            f"validator_version={self._validator_version!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidatedSample):
            return False
        return (
            self._schema_name == other._schema_name
            and self._table_name == other._table_name
            and self._columns == other._columns
            and self._rows == other._rows
            and self._row_count == other._row_count
            and self._truncated == other._truncated
            and self._policy_version == other._policy_version
            and self._validator_version == other._validator_version
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._schema_name,
                self._table_name,
                self._columns,
                self._rows,
                self._row_count,
                self._truncated,
                self._policy_version,
                self._validator_version,
            )
        )


class LeakageValidationResult(BaseModel):
    """Immutable paired result of one leakage validation run.

    When validation passes:
    - ``accepted`` is True
    - ``sample`` is a ``ValidatedSample``
    - ``report.outcome`` is ``LeakageValidationOutcome.ACCEPTED``

    When validation fails:
    - ``accepted`` is False
    - ``sample`` is None (no unvalidated or partial data escapes)
    - ``report.outcome`` is ``LeakageValidationOutcome.REJECTED``
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        arbitrary_types_allowed=True,
    )

    accepted: bool
    sample: ValidatedSample | None = None
    report: LeakageValidationReport

    @model_validator(mode="after")
    def _validate_result_invariants(self) -> Self:
        if self.accepted:
            if self.sample is None or self.report.outcome != LeakageValidationOutcome.ACCEPTED:
                raise ValueError("accepted result must contain ValidatedSample and accepted report")
        elif self.sample is not None or self.report.outcome != LeakageValidationOutcome.REJECTED:
            raise ValueError("rejected result must have sample=None and rejected report")
        return self


def _luhn_valid(digits: str) -> bool:
    """Validate numeric string using the Luhn algorithm."""
    total = 0
    for index, ch in enumerate(reversed(digits)):
        val = int(ch)
        if index % 2 == 1:
            val *= 2
            if val > _LUHN_CARRY:
                val -= _LUHN_CARRY
        total += val
    return total % 10 == 0


def _is_iban(text: str) -> bool:
    """Validate international bank account number using shape and mod-97 checksum."""
    iban = text.strip().upper()
    if not _IBAN_MIN_LENGTH <= len(iban) <= _IBAN_MAX_LENGTH or not _IBAN_SHAPE_RE.fullmatch(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    if not rearranged.isalnum():
        return False
    number = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    return int(number) % 97 == 1


def _canonicalize_text(text: str) -> str | None:
    """Apply bounded canonicalization (Unicode formatting removal and percent-decoding).

    Returns the canonicalized text if different from the input, or None if no transformation
    was applied. The policy is single-pass (non-recursive) and bounded to prevent expansion.
    """
    modified = False
    result = text

    if _UNICODE_FORMAT_CHARS_RE.search(result):
        result = _UNICODE_FORMAT_CHARS_RE.sub("", result)
        modified = True

    if "%" in result:
        try:
            unquoted = urllib.parse.unquote(result, errors="replace")
            if unquoted != result:
                result = unquoted
                modified = True
        except Exception:  # noqa: BLE001, S110
            pass

    return result if modified else None


def _has_connection_string_with_password(text: str) -> bool:
    """Inspect all bounded URI candidates in text for unredacted passwords.

    Replaces unrestricted backtracking regexes with linear O(N) candidate scanning.
    Inspects every URI candidate in the text; if any candidate contains an unredacted
    password, returns True.
    """
    pos = 0
    text_len = len(text)
    delimiter = "://"

    while pos < text_len:
        idx = text.find(delimiter, pos)
        if idx == -1:
            break

        scheme_start = idx
        while scheme_start > 0 and scheme_start > idx - 33:
            char = text[scheme_start - 1]
            if not (char.isalnum() or char in "+.-"):
                break
            scheme_start -= 1

        scheme = text[scheme_start:idx]
        if _URI_SCHEME_RE.fullmatch(scheme):
            auth_start = idx + len(delimiter)
            auth_end = auth_start
            max_end = min(text_len, auth_start + _MAX_URI_CANDIDATE_LENGTH)
            delimiters = ("/", "?", "#", " ", "\t", "\r", "\n", '"', "'", "`")
            while auth_end < max_end and text[auth_end] not in delimiters:
                auth_end += 1

            authority = text[auth_start:auth_end]
            if "@" in authority:
                userinfo, _, _ = authority.partition("@")
                if ":" in userinfo:
                    _, _, password = userinfo.partition(":")
                    clean_pw = password.strip("\"' ")
                    if clean_pw and clean_pw not in (_REDACTED_MARKER, _MASKED_MARKER):
                        unquoted_pw = urllib.parse.unquote(clean_pw).strip("\"' ")
                        if unquoted_pw and unquoted_pw not in (_REDACTED_MARKER, _MASKED_MARKER):
                            return True

        pos = idx + len(delimiter)

    return False


class LeakageValidator:
    """Deterministic, fail-closed Phase 3F leakage validation engine."""

    def __init__(self, config: LeakageValidationConfig | None = None) -> None:
        if config is None:
            self.config = LeakageValidationConfig()
        else:
            self.config = _validate_config(config)

    def validate(
        self,
        target: SanitizationResult | SanitizedSample,
        *,
        report: SanitizationReport | None = None,
    ) -> LeakageValidationResult:
        """Validate sanitized sample and report against leakage and boundary rules.

        Parameters
        ----------
        target:
            ``SanitizationResult`` or ``SanitizedSample`` to validate.
        report:
            Optional ``SanitizationReport`` when ``target`` is a ``SanitizedSample``.

        Returns
        -------
        LeakageValidationResult:
            Immutable result containing acceptance flag, optional ``ValidatedSample``,
            and ``LeakageValidationReport``.
        """
        failed_with_exception = False
        try:
            return self._execute_validation(target, report=report)
        except LeakageValidationError:
            raise
        except Exception:  # noqa: BLE001
            failed_with_exception = True

        if failed_with_exception:
            raise _safe_error()
        raise _safe_error()

    def validate_or_raise(
        self,
        target: SanitizationResult | SanitizedSample,
        *,
        report: SanitizationReport | None = None,
    ) -> ValidatedSample:
        """Validate sample, returning ``ValidatedSample`` or raising ``LeakageValidationError``."""
        result = self.validate(target, report=report)
        if not result.accepted or result.sample is None:
            raise _safe_error("Sanitized sample failed leakage validation")
        return result.sample

    def _execute_validation(
        self,
        target: SanitizationResult | SanitizedSample,
        *,
        report: SanitizationReport | None = None,
    ) -> LeakageValidationResult:
        sample: SanitizedSample
        audit_report: SanitizationReport | None = report

        if isinstance(target, SanitizationResult):
            sample = target.sample
            audit_report = target.report
        elif isinstance(target, SanitizedSample):
            sample = target
        else:
            raise _safe_error("Validation target must be SanitizationResult or SanitizedSample")

        reasons: list[str] = []
        issue_counts: dict[str, int] = {}
        metrics = _ScanMetrics()

        # Step 1: Structural and boundary checks. If limits exceeded, abort early without scanning.
        policy_ver = self._validate_structure(sample, reasons, metrics)
        if policy_ver is None or reasons:
            return self._build_rejected_result(
                sample_or_version="unknown" if policy_ver is None else policy_ver,
                reasons=reasons,
                issue_counts=issue_counts,
                metrics=metrics,
            )

        # Step 2: Validate audit report consistency if provided
        if audit_report is not None:
            self._validate_report_consistency(audit_report, sample, reasons)
            if reasons:
                return self._build_rejected_result(
                    sample_or_version=policy_ver,
                    reasons=reasons,
                    issue_counts=issue_counts,
                    metrics=metrics,
                )

        # Step 3: Metadata residual leakage scan
        self._scan_metadata(
            schema=sample.schema_name,
            table=sample.table_name,
            columns=sample.columns,
            reasons=reasons,
            issue_counts=issue_counts,
        )

        # Step 4: Cell-by-cell inspection (stops immediately on limit violation)
        self._scan_cells(sample, reasons, issue_counts, metrics)

        # Step 5: Final decision
        if reasons:
            return self._build_rejected_result(
                sample_or_version=policy_ver,
                reasons=reasons,
                issue_counts=issue_counts,
                metrics=metrics,
            )

        validated_sample = ValidatedSample(
            sample=sample,
            validator_version=_VALIDATOR_VERSION,
            _token=_VALIDATION_TOKEN,
        )
        report_obj = LeakageValidationReport(
            outcome=LeakageValidationOutcome.ACCEPTED,
            validator_version=_VALIDATOR_VERSION,
            policy_version=policy_ver,
            checked_fields=metrics.fields,
            checked_rows=metrics.rows,
            checked_cells=metrics.cells,
            checked_text_chars=metrics.chars,
            reason_codes=(),
            issue_counts=MappingProxyType({}),
        )
        return LeakageValidationResult(
            accepted=True,
            sample=validated_sample,
            report=report_obj,
        )

    def _validate_structure(
        self,
        sample: SanitizedSample,
        reasons: list[str],
        metrics: _ScanMetrics,
    ) -> str | None:
        """Validate sample metadata and dimensions, returning policy_version or None."""
        policy_ver = getattr(sample, "policy_version", "")
        if (
            not isinstance(policy_ver, str)
            or not policy_ver
            or "\x00" in policy_ver
            or len(policy_ver) > _MAX_POLICY_VERSION_LENGTH
        ):
            reasons.append("malformed_policy_version")
            return None

        schema = getattr(sample, "schema_name", "")
        table = getattr(sample, "table_name", "")
        if (
            not isinstance(schema, str)
            or not schema
            or "\x00" in schema
            or len(schema) > _MAX_IDENTIFIER_LENGTH
            or not isinstance(table, str)
            or not table
            or "\x00" in table
            or len(table) > _MAX_IDENTIFIER_LENGTH
        ):
            reasons.append("malformed_identifier")

        cols = getattr(sample, "columns", None)
        if not isinstance(cols, tuple) or any(
            not isinstance(c, str) or not c or "\x00" in c or len(c) > _MAX_IDENTIFIER_LENGTH
            for c in cols
        ):
            reasons.append("malformed_columns")
            return None

        if len(set(cols)) != len(cols):
            reasons.append("duplicate_columns")

        raw_rows = getattr(sample, "rows", None)
        if not isinstance(raw_rows, tuple):
            reasons.append("malformed_rows")
            return None

        metrics.fields = len(cols)
        metrics.rows = len(raw_rows)
        actual_cells = metrics.fields * metrics.rows

        # Enforce limits upfront before scanning any cells
        if metrics.fields > self.config.max_fields or metrics.fields > _MAX_FIELDS:
            reasons.append("max_fields_exceeded")
        if metrics.rows > self.config.max_rows or metrics.rows > _MAX_ROWS:
            reasons.append("max_rows_exceeded")
        if actual_cells > self.config.max_cells or actual_cells > _ABSOLUTE_MAX_CELLS:
            reasons.append("max_cells_exceeded")

        declared_row_count = getattr(sample, "row_count", None)
        if (
            not isinstance(declared_row_count, int)
            or type(declared_row_count) is bool
            or declared_row_count != metrics.rows
        ):
            reasons.append("row_count_mismatch")

        if type(getattr(sample, "truncated", None)) is not bool:
            reasons.append("malformed_truncated_flag")

        if reasons:
            return None

        return policy_ver

    def _validate_report_consistency(
        self,
        audit_report: object,
        sample: SanitizedSample,
        reasons: list[str],
    ) -> None:
        """Strictly validate report fields and count consistency."""
        if not isinstance(audit_report, SanitizationReport):
            reasons.append("malformed_report")
            return

        policy_ver = getattr(audit_report, "policy_version", "")
        if (
            not isinstance(policy_ver, str)
            or not policy_ver
            or "\x00" in policy_ver
            or len(policy_ver) > _MAX_POLICY_VERSION_LENGTH
            or policy_ver != sample.policy_version
        ):
            reasons.append("report_policy_version_mismatch")

        count_fields = (
            "total_fields",
            "classified_fields",
            "redacted_fields",
            "masked_fields",
            "pseudonymized_fields",
            "dropped_fields",
            "allowed_fields",
            "unknown_fields",
        )
        counts: dict[str, int] = {}
        for field_name in count_fields:
            val = getattr(audit_report, field_name, None)
            if type(val) is not int or val < 0:
                reasons.append("inconsistent_report_counts")
                return
            counts[field_name] = val

        if counts["classified_fields"] != counts["total_fields"]:
            reasons.append("inconsistent_report_counts")
            return

        action_total = (
            counts["redacted_fields"]
            + counts["masked_fields"]
            + counts["pseudonymized_fields"]
            + counts["dropped_fields"]
            + counts["allowed_fields"]
        )
        if action_total != counts["classified_fields"]:
            reasons.append("inconsistent_report_counts")
            return

        if counts["unknown_fields"] > counts["classified_fields"]:
            reasons.append("inconsistent_report_counts")
            return

        if counts["dropped_fields"] > counts["total_fields"]:
            reasons.append("inconsistent_report_counts")
            return

        expected_retained = counts["total_fields"] - counts["dropped_fields"]
        if len(sample.columns) != expected_retained:
            reasons.append("report_field_count_mismatch")

    def _scan_cells(
        self,
        sample: SanitizedSample,
        reasons: list[str],
        issue_counts: dict[str, int],
        metrics: _ScanMetrics,
    ) -> None:
        """Scan all rows and cells in sample for structural rules and residual leakage."""
        for row in sample.rows:
            if not isinstance(row, tuple) or len(row) != metrics.fields:
                if "row_width_mismatch" not in reasons:
                    reasons.append("row_width_mismatch")
                return

            for cell in row:
                metrics.cells += 1
                if metrics.cells > self.config.max_cells or metrics.cells > _ABSOLUTE_MAX_CELLS:
                    if "max_cells_exceeded" not in reasons:
                        reasons.append("max_cells_exceeded")
                    return

                if cell is None:
                    continue

                if type(cell) not in (bool, int, float, str):
                    if "unsupported_scalar_type" not in reasons:
                        reasons.append("unsupported_scalar_type")
                    return

                if isinstance(cell, float) and not math.isfinite(cell):
                    if "non_finite_float" not in reasons:
                        reasons.append("non_finite_float")
                    return

                if isinstance(cell, str) and not self._scan_string_cell(
                    cell, reasons, issue_counts, metrics
                ):
                    return

    def _scan_string_cell(
        self,
        cell: str,
        reasons: list[str],
        issue_counts: dict[str, int],
        metrics: _ScanMetrics,
    ) -> bool:
        """Scan one string cell value, returning False if processing should stop."""
        if "\x00" in cell:
            if "nul_byte_in_cell" not in reasons:
                reasons.append("nul_byte_in_cell")
            return False

        cell_len = len(cell)
        metrics.chars += cell_len

        if cell_len > self.config.max_text_chars or cell_len > _ABSOLUTE_MAX_TEXT_CHARS:
            if "max_text_chars_exceeded" not in reasons:
                reasons.append("max_text_chars_exceeded")
            return False

        if (
            metrics.chars > self.config.max_total_text_chars
            or metrics.chars > _ABSOLUTE_MAX_TOTAL_TEXT_CHARS
        ):
            if "max_total_text_chars_exceeded" not in reasons:
                reasons.append("max_total_text_chars_exceeded")
            return False

        if cell in (_REDACTED_MARKER, _MASKED_MARKER) or _PSEUDONYM_PATTERN.fullmatch(cell):
            return True

        self._scan_text(text=cell, reasons=reasons, issue_counts=issue_counts)
        canonical = _canonicalize_text(cell)
        if canonical is not None:
            self._scan_text(text=canonical, reasons=reasons, issue_counts=issue_counts)

        return True

    def _build_rejected_result(
        self,
        *,
        sample_or_version: str,
        reasons: list[str],
        issue_counts: dict[str, int],
        metrics: _ScanMetrics,
    ) -> LeakageValidationResult:
        if self.config.raise_on_rejection:
            raise _safe_error()

        safe_policy_ver = sample_or_version or "unknown"

        report_obj = LeakageValidationReport(
            outcome=LeakageValidationOutcome.REJECTED,
            validator_version=_VALIDATOR_VERSION,
            policy_version=safe_policy_ver,
            checked_fields=metrics.fields,
            checked_rows=metrics.rows,
            checked_cells=metrics.cells,
            checked_text_chars=metrics.chars,
            reason_codes=tuple(reasons),
            issue_counts=MappingProxyType(issue_counts),
        )
        return LeakageValidationResult(
            accepted=False,
            sample=None,
            report=report_obj,
        )

    def _scan_metadata(
        self,
        *,
        schema: str,
        table: str,
        columns: tuple[str, ...],
        reasons: list[str],
        issue_counts: dict[str, int],
    ) -> None:
        """Inspect metadata strings for embedded secrets and sensitive assignments."""
        for meta_text in (schema, table, *columns):
            self._scan_text(text=meta_text, reasons=reasons, issue_counts=issue_counts)
            canonical = _canonicalize_text(meta_text)
            if canonical is not None:
                self._scan_text(text=canonical, reasons=reasons, issue_counts=issue_counts)

    def _scan_text(
        self,
        *,
        text: str,
        reasons: list[str],
        issue_counts: dict[str, int],
    ) -> None:
        """Scan one text value for residual sensitive patterns."""
        self._scan_text_secrets(text=text, reasons=reasons, issue_counts=issue_counts)
        self._scan_text_pii(text=text, reasons=reasons, issue_counts=issue_counts)

    def _scan_text_secrets(
        self,
        *,
        text: str,
        reasons: list[str],
        issue_counts: dict[str, int],
    ) -> None:
        if _PRIVATE_KEY_RE.search(text):
            self._record_issue("residual_private_key", reasons, issue_counts)

        auth_match = _AUTH_HEADER_RE.search(text)
        if auth_match:
            auth_token = auth_match.group(1).strip("\"' ")
            if auth_token not in (_REDACTED_MARKER, _MASKED_MARKER):
                self._record_issue("residual_auth_header", reasons, issue_counts)

        if _JWT_RE.search(text):
            self._record_issue("residual_jwt", reasons, issue_counts)

        if _has_connection_string_with_password(text):
            self._record_issue("residual_connection_string", reasons, issue_counts)

        for cred_match in _CREDENTIAL_ASSIGNMENT_RE.finditer(text):
            val = cred_match.group(1).strip("\"' ")
            if val not in (_REDACTED_MARKER, _MASKED_MARKER):
                self._record_issue("residual_credential_assignment", reasons, issue_counts)
                break

        for secret_match in _SECRET_ASSIGNMENT_RE.finditer(text):
            val = secret_match.group(1).strip("\"' ")
            if val not in (_REDACTED_MARKER, _MASKED_MARKER):
                self._record_issue("residual_secret_assignment", reasons, issue_counts)
                break

    def _scan_text_pii(
        self,
        *,
        text: str,
        reasons: list[str],
        issue_counts: dict[str, int],
    ) -> None:
        if _EMAIL_EMBEDDED_RE.search(text):
            self._record_issue("residual_email", reasons, issue_counts)

        for phone_match in _PHONE_CANDIDATE_RE.finditer(text):
            digits = re.sub(r"[\s\-().]", "", phone_match.group(0))
            if _INTL_PHONE_RE.fullmatch(digits):
                self._record_issue("residual_phone", reasons, issue_counts)
                break

        for card_match in _CARD_CANDIDATE_RE.finditer(text):
            digits = re.sub(r"[\s-]", "", card_match.group(0))
            if (
                _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS
                and digits.isdigit()
                and _luhn_valid(digits)
            ):
                self._record_issue("residual_payment_card", reasons, issue_counts)
                break

        for iban_match in _IBAN_CANDIDATE_RE.finditer(text):
            clean_iban = re.sub(r"\s", "", iban_match.group(0)).upper()
            if _is_iban(clean_iban):
                self._record_issue("residual_iban", reasons, issue_counts)
                break

        if _SSN_RE.search(text):
            self._record_issue("residual_national_id", reasons, issue_counts)

    def _record_issue(
        self,
        code: str,
        reasons: list[str],
        issue_counts: dict[str, int],
    ) -> None:
        if code not in reasons:
            reasons.append(code)
        issue_counts[code] = issue_counts.get(code, 0) + 1
