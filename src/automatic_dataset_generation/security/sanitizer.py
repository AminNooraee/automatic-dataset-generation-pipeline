"""Deterministic, fail-closed Phase 3E sanitization orchestrator.

Phase 3E is the aggregation layer between the Phase 3B/3C detectors (which classify fields) and
Phase 3F (which validates that the completed ``SanitizedSample`` is leakage-free before LLM
exposure).

Responsibilities
----------------
1. Accept a raw ``SampleResult`` (the only input; no detectors pre-run externally).
2. Validate sample structure, dimensions, and limits against actual data shape.
3. Run ``SecretCredentialDetector`` and ``PIIDetector`` over the same input.
4. Merge their per-field classifications with a documented, deterministic precedence rule that
   never weakens protection (see ``_merge_classifications``).
5. Classify fields that neither detector flagged as ``UNKNOWN`` (fail-closed) unless included in an
   explicit, narrow, optional ``non_sensitive_allowlist``.
6. Resolve each merged classification through ``SanitizationPolicy``.
7. Apply ``SanitizationTransformer`` to every cell of every classified field.
8. Distinguish genuinely dropped columns from legitimate ``None`` values.
9. Produce an immutable ``SanitizedSample`` and a ``SanitizationReport``.
10. Return both in an immutable ``SanitizationResult``; on any exception the entire result is
    discarded atomically (no partial output is returned).

Non-responsibilities (deferred phases)
---------------------------------------
- Leakage validation (Phase 3F) — ``SanitizationResult.sample`` is NOT LLM-safe without it.
- Database connections, MCP transports, agents, LLM calls.

Security invariants (maintained throughout)
--------------------------------------------
- Unclassified fields default to ``UNKNOWN`` and are fail-closed (redacted by default policy).
- An optional ``non_sensitive_allowlist`` never overrides a positive detector finding.
- Merge precedence: policy-aware protection rank (DROP > REDACT / MASK > PSEUDONYMIZE > ALLOW)
  with sensitivity severity tie-break (CREDENTIAL > SECRET > PII > UNKNOWN); a stronger finding
  from one detector is never weakened by a weaker or absent finding from the other.
- Pseudonymization requires a properly configured key in ``SanitizationTransformConfig``
  whenever any field resolves to ``SanitizationAction.PSEUDONYMIZE``, even if sampled values
  are null or empty.
- Detected sensitive values (credentials, secrets, PII) and unknown values are never exposed raw
  in results without policy protection (redacted, masked, pseudonymized, or dropped).
- Explicitly approved non-sensitive values (via ``non_sensitive_allowlist``) may remain in
  ``SanitizationResult.sample`` in normalized scalar domain form.
- Raw sensitive values, credentials, matched substrings, and pseudonymization keys never appear
  in logs, audit reports, public error diagnostics, or default ``repr()`` representations.
- Payload serialization (such as ``model_dump()`` or ``model_dump_json()``) carries transformed
  and allowed cell values and is NOT log-safe; diagnostic logging must use ``SanitizationReport``
  or default model representations.
- Public ``SanitizationOrchestratorError`` exceptions are completely detached from internal
  exception chains (``__context__`` and ``__cause__`` are stripped) so that sensitive exception
  messages do not leak through standard exception chains or formatted tracebacks. Diagnostic
  tools that capture arbitrary raw execution frame locals of failing components are outside
  this guarantee.
- Bounded processing: dimensions and cell counts are validated against limits using actual data
  dimensions before scanning begins.
- Atomic failure: exceptions propagate without returning partial output.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from types import MappingProxyType
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from automatic_dataset_generation.database.models import SampleResult
from automatic_dataset_generation.security.models import (
    FieldClassification,
    FieldReference,
    SanitizationAction,
    SanitizationDecision,
    SanitizationReport,
    SanitizedSample,
    SanitizedValue,
    SensitivityClass,
)
from automatic_dataset_generation.security.pii_detection import (
    PIIDetectionConfig,
    PIIDetectionError,
    PIIDetectionResult,
    PIIDetector,
)
from automatic_dataset_generation.security.policy import SanitizationPolicy
from automatic_dataset_generation.security.secret_detection import (
    SecretCredentialDetector,
    SecretDetectionConfig,
    SecretDetectionError,
    SecretDetectionResult,
)
from automatic_dataset_generation.security.transforms import (
    SanitizationTransformConfig,
    SanitizationTransformer,
    SanitizationTransformError,
)

_logger = logging.getLogger(__name__)

# Protection rank for policy actions — higher rank provides strictly stronger data protection.
# DROP (eliminates column entirely) > REDACT / MASK (replaces value with opaque fixed marker) >
# PSEUDONYMIZE (replaces with keyed token, preserves linkage) > ALLOW (passes value through).
_ACTION_PROTECTION_RANK: Final[dict[SanitizationAction, int]] = {
    SanitizationAction.ALLOW: 0,
    SanitizationAction.PSEUDONYMIZE: 1,
    SanitizationAction.MASK: 2,
    SanitizationAction.REDACT: 2,
    SanitizationAction.DROP: 3,
}

# Sensitivity severity rank used as tie-breaker when policy actions have equal protection rank.
# CREDENTIAL > SECRET > PII > UNKNOWN > NON_SENSITIVE.
_SENSITIVITY_SEVERITY_RANK: Final[dict[SensitivityClass, int]] = {
    SensitivityClass.NON_SENSITIVE: 0,
    SensitivityClass.UNKNOWN: 1,
    SensitivityClass.PII: 2,
    SensitivityClass.SECRET: 3,
    SensitivityClass.CREDENTIAL: 4,
}

_SAFE_ERROR_MESSAGE: Final[str] = "Sanitization orchestration could not complete safely"
_ORCHESTRATOR_VERSION: Final[str] = "sanitization_orchestrator.v1"

# Hard absolute limits to prevent processing-limit bypasses and pathological inputs.
_MAX_IDENTIFIER_LENGTH: Final[int] = 128
_MAX_FIELDS: Final[int] = 10_000
_MAX_ROWS: Final[int] = 1_000_000
_ABSOLUTE_MAX_CELLS: Final[int] = 1_000_000

_DEFAULT_MAX_FIELDS: Final[int] = 1_000
_DEFAULT_MAX_ROWS: Final[int] = 10_000
_DEFAULT_MAX_CELLS: Final[int] = 100_000


class SanitizationOrchestratorError(RuntimeError):
    """Safe public failure raised when orchestration cannot complete.

    The message is always a fixed, low-information string; it never contains raw values,
    matched substrings, keys, or internal exception details. Public exceptions are completely
    detached from internal exception chains (``__context__`` and ``__cause__`` are stripped).
    """


def _safe_error() -> SanitizationOrchestratorError:
    """Construct a public SanitizationOrchestratorError detached from exception chains."""
    err = SanitizationOrchestratorError(_SAFE_ERROR_MESSAGE)
    err.__context__ = None
    err.__cause__ = None
    err.__suppress_context__ = True
    return err


class SanitizationOrchestratorConfig(BaseModel):
    """Immutable configuration for one orchestrator instance.

    Parameters
    ----------
    policy:
        The fail-closed ``SanitizationPolicy`` that maps sensitivity classes to actions. Defaults
        to the default policy (``non_sensitive -> allow``, ``pii -> pseudonymize``,
        ``secret/credential/unknown -> redact``).
    transform_config:
        ``SanitizationTransformConfig`` passed to each ``SanitizationTransformer`` call. Callers
        that need ``pseudonymize`` support must supply a ``pseudonymization_key`` here.
    secret_config:
        Resource limits for ``SecretCredentialDetector``. Defaults to the detector's defaults.
    pii_config:
        Resource limits for ``PIIDetector``. Defaults to the detector's defaults.
    non_sensitive_allowlist:
        Optional frozenset of column names pre-declared non-sensitive. This allowlist is applied
        ONLY when both detectors return no finding for that column. A positive finding from either
        detector always takes precedence — the allowlist cannot override it. Column matching is
        case-sensitive and exact.
    max_fields:
        Maximum allowed columns in a sample, enforced even on zero-row samples.
    max_rows:
        Maximum allowed rows in a sample, enforced even on zero-column samples.
    max_cells:
        Maximum allowed total cells (actual_rows * actual_columns) in a sample.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    policy: SanitizationPolicy = Field(default_factory=SanitizationPolicy)
    transform_config: SanitizationTransformConfig = Field(
        default_factory=SanitizationTransformConfig
    )
    secret_config: SecretDetectionConfig = Field(default_factory=SecretDetectionConfig)
    pii_config: PIIDetectionConfig = Field(default_factory=PIIDetectionConfig)
    non_sensitive_allowlist: frozenset[str] = Field(default_factory=frozenset)
    max_fields: int = Field(default=_DEFAULT_MAX_FIELDS, gt=0, le=_MAX_FIELDS, strict=True)
    max_rows: int = Field(default=_DEFAULT_MAX_ROWS, gt=0, le=_MAX_ROWS, strict=True)
    max_cells: int = Field(default=_DEFAULT_MAX_CELLS, gt=0, le=_ABSOLUTE_MAX_CELLS, strict=True)

    @field_validator("non_sensitive_allowlist", mode="before")
    @classmethod
    def _validate_allowlist(cls, value: object) -> frozenset[str]:
        if value is None:
            return frozenset()
        if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
            raise ValueError(  # noqa: TRY004
                "non_sensitive_allowlist must be an iterable of non-empty strings"
            )

        entries: set[str] = set()
        for consumed, item in enumerate(value, start=1):
            if consumed > _MAX_FIELDS:
                raise ValueError("allowlist exceeds maximum allowed entries")
            if (
                not isinstance(item, str)
                or not item
                or len(item) > _MAX_IDENTIFIER_LENGTH
                or "\x00" in item
            ):
                raise ValueError(
                    "allowlist entries must be non-empty text without NUL within length limit"
                )
            entries.add(item)
        return frozenset(entries)

    @model_validator(mode="after")
    def _validate_config_bounds(self) -> Self:
        if len(self.non_sensitive_allowlist) > self.max_fields:
            raise ValueError("non_sensitive_allowlist size cannot exceed max_fields")
        return self


class SanitizationResult(BaseModel):
    """Immutable paired output of one successful orchestration run.

    .. warning::
        ``sample`` is **not** LLM-safe without Phase 3F leakage validation. Phase 3E sanitizes
        the data according to policy, but it does not verify that no residual sensitive content
        remains. Phase 3F is a mandatory additional step before any LLM exposure.

    .. note::
        Payload serialization via ``model_dump()`` or ``model_dump_json()`` includes sanitized and
        allowed row contents and is **not** log-safe. Only ``SanitizationReport`` and default
        ``repr()`` representations are safe for diagnostic logging.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    sample: SanitizedSample
    report: SanitizationReport


def _merge_classifications(
    secret_result: SecretDetectionResult,
    pii_result: PIIDetectionResult,
    policy: SanitizationPolicy | None = None,
) -> dict[str, FieldClassification]:
    """Merge per-column findings from both detectors using a deterministic, policy-aware rule.

    Precedence rule (documented, deterministic, never-weaken)
    ---------------------------------------------------------
    For each column that appeared in at least one detector's findings:
    1. If only one detector found a signal, that finding is used.
    2. If both detectors found a signal:
       a. Compare the protection strength of their resolved actions under ``policy``:
          ``_ACTION_PROTECTION_RANK[action]`` (DROP > REDACT / MASK > PSEUDONYMIZE > ALLOW).
          The classification yielding strictly stronger protection wins.
       b. If actions have equal protection rank (e.g. both resolve to REDACT):
          Break ties by sensitivity severity: CREDENTIAL > SECRET > PII > UNKNOWN.
       c. If sensitivities are also equal (e.g. both UNKNOWN):
          Break ties by confidence (higher wins).
       d. If confidence is also equal:
          The secret detector finding is kept (conservative default).
    3. A finding from either detector is never weakened or discarded due to the absence or weaker
       finding from the other detector.

    Returns a ``dict[column_name -> merged FieldClassification]``. Fields with no finding in
    either detector are absent from the returned dictionary.
    """
    effective_policy = policy if policy is not None else SanitizationPolicy()
    merged: dict[str, FieldClassification] = {}

    for clf in secret_result.classifications:
        merged[clf.field.column_name] = clf

    for clf in pii_result.classifications:
        col = clf.field.column_name
        existing = merged.get(col)
        if existing is None:
            merged[col] = clf
            continue

        existing_action = effective_policy.action_for(existing.sensitivity)
        candidate_action = effective_policy.action_for(clf.sensitivity)

        existing_strength = _ACTION_PROTECTION_RANK.get(existing_action, 0)
        candidate_strength = _ACTION_PROTECTION_RANK.get(candidate_action, 0)

        if candidate_strength > existing_strength:
            merged[col] = clf
        elif candidate_strength == existing_strength:
            existing_sev = _SENSITIVITY_SEVERITY_RANK.get(existing.sensitivity, 0)
            candidate_sev = _SENSITIVITY_SEVERITY_RANK.get(clf.sensitivity, 0)
            if candidate_sev > existing_sev or (
                candidate_sev == existing_sev and clf.confidence > existing.confidence
            ):
                merged[col] = clf

    return merged


def _resolve_decisions(
    sample: SampleResult,
    merged_by_col: Mapping[str, FieldClassification],
    policy: SanitizationPolicy,
    allowlist: frozenset[str],
) -> MappingProxyType[str, SanitizationDecision]:
    """Resolve a SanitizationDecision for every column in sample."""
    decisions: dict[str, SanitizationDecision] = {}
    for column in sample.columns:
        clf = merged_by_col.get(column)
        if clf is None:
            sensitivity = (
                SensitivityClass.NON_SENSITIVE if column in allowlist else SensitivityClass.UNKNOWN
            )
            ref = FieldReference(
                schema_name=sample.schema_name,
                table_name=sample.table_name,
                column_name=column,
            )
            clf = FieldClassification(
                field=ref,
                sensitivity=sensitivity,
                confidence=0.0,
                detector=_ORCHESTRATOR_VERSION,
            )
        decisions[column] = policy.decide(clf)
    return MappingProxyType(decisions)


def _build_report(
    total_fields: int,
    policy_version: str,
    decisions: Mapping[str, SanitizationDecision],
) -> SanitizationReport:
    """Calculate counts and construct an immutable SanitizationReport."""
    redacted_count = 0
    masked_count = 0
    pseudonymized_count = 0
    dropped_count = 0
    allowed_count = 0
    unknown_count = 0

    for decision in decisions.values():
        match decision.action:
            case SanitizationAction.REDACT:
                redacted_count += 1
            case SanitizationAction.MASK:
                masked_count += 1
            case SanitizationAction.PSEUDONYMIZE:
                pseudonymized_count += 1
            case SanitizationAction.DROP:
                dropped_count += 1
            case SanitizationAction.ALLOW:
                allowed_count += 1
            case _:  # pragma: no cover
                raise _safe_error()

        if decision.sensitivity is SensitivityClass.UNKNOWN:
            unknown_count += 1

    return SanitizationReport(
        policy_version=policy_version,
        total_fields=total_fields,
        classified_fields=total_fields,
        redacted_fields=redacted_count,
        masked_fields=masked_count,
        pseudonymized_fields=pseudonymized_count,
        dropped_fields=dropped_count,
        allowed_fields=allowed_count,
        unknown_fields=unknown_count,
    )


def _transform_rows(
    sample: SampleResult,
    kept_columns: tuple[str, ...],
    decisions: Mapping[str, SanitizationDecision],
    transformer: SanitizationTransformer,
) -> tuple[tuple[SanitizedValue, ...], ...]:
    """Transform row cells for kept columns only."""
    column_index_map: dict[str, int] = {col: i for i, col in enumerate(sample.columns)}
    sanitized_rows: list[tuple[SanitizedValue, ...]] = []
    for raw_row in sample.rows:
        sanitized_row: list[SanitizedValue] = []
        for col in kept_columns:
            raw_value = raw_row[column_index_map[col]]
            decision = decisions[col]
            transform_result = transformer.transform(raw_value, decision)
            sanitized_row.append(transform_result.value)
        sanitized_rows.append(tuple(sanitized_row))
    return tuple(sanitized_rows)


def _validate_sample_shape(
    sample: SampleResult,
    config: SanitizationOrchestratorConfig,
) -> None:
    """Validate sample structure, actual dimensions, and bounds fail-closed."""
    if (
        not isinstance(sample.schema_name, str)
        or not sample.schema_name
        or len(sample.schema_name) > _MAX_IDENTIFIER_LENGTH
        or "\x00" in sample.schema_name
        or not isinstance(sample.table_name, str)
        or not sample.table_name
        or len(sample.table_name) > _MAX_IDENTIFIER_LENGTH
        or "\x00" in sample.table_name
    ):
        raise _safe_error()

    if not isinstance(sample.columns, tuple):
        raise _safe_error()
    actual_fields = len(sample.columns)
    if actual_fields > config.max_fields:
        raise _safe_error()

    for col in sample.columns:
        if (
            not isinstance(col, str)
            or not col
            or len(col) > _MAX_IDENTIFIER_LENGTH
            or "\x00" in col
        ):
            raise _safe_error()

    if len(set(sample.columns)) != actual_fields:
        raise _safe_error()

    if not isinstance(sample.rows, tuple):
        raise _safe_error()
    actual_rows = len(sample.rows)
    if not isinstance(sample.row_count, int) or sample.row_count != actual_rows:
        raise _safe_error()
    if actual_rows > config.max_rows:
        raise _safe_error()

    for row in sample.rows:
        if not isinstance(row, tuple) or len(row) != actual_fields:
            raise _safe_error()

    actual_cells = actual_rows * actual_fields
    if actual_cells > config.max_cells or actual_cells > _ABSOLUTE_MAX_CELLS:
        raise _safe_error()


@dataclass(frozen=True, slots=True)
class SanitizationOrchestrator:
    """Deterministic, fail-closed sanitization orchestrator (Phase 3E).

    Runs ``SecretCredentialDetector`` and ``PIIDetector`` over a raw ``SampleResult``, merges
    their findings, resolves each field's action through ``SanitizationPolicy``, applies
    ``SanitizationTransformer`` per cell, and constructs a ``SanitizedSample`` +
    ``SanitizationReport``.

    Exceptions are propagated without returning partial output (atomic failure).

    .. warning::
        The returned ``SanitizationResult.sample`` is NOT leakage-validated. Phase 3F must run
        before any ``SanitizedSample`` may be sent to an LLM.

    Examples
    --------
    >>> from pydantic import SecretStr
    >>> from automatic_dataset_generation.database.models import SampleResult
    >>> from automatic_dataset_generation.security.sanitizer import (
    ...     SanitizationOrchestrator,
    ...     SanitizationOrchestratorConfig,
    ... )
    >>> from automatic_dataset_generation.security.transforms import SanitizationTransformConfig
    >>> cfg = SanitizationOrchestratorConfig(
    ...     transform_config=SanitizationTransformConfig(
    ...         pseudonymization_key=SecretStr("k" * 64)
    ...     )
    ... )
    >>> orchestrator = SanitizationOrchestrator(config=cfg)
    >>> sample = SampleResult(
    ...     schema_name="public",
    ...     table_name="users",
    ...     columns=("id", "email"),
    ...     rows=((1, "alice@example.com"),),
    ...     row_count=1,
    ...     truncated=False,
    ... )
    >>> result = orchestrator.sanitize(sample)
    >>> result.sample.columns
    ('id', 'email')
    """

    config: SanitizationOrchestratorConfig = dataclass_field(
        default_factory=SanitizationOrchestratorConfig
    )

    def __post_init__(self) -> None:
        if not isinstance(self.config, SanitizationOrchestratorConfig):
            raise TypeError("config must be a SanitizationOrchestratorConfig")

    def sanitize(self, sample: SampleResult) -> SanitizationResult:
        """Orchestrate full field-level sanitization of one raw ``SampleResult``.

        Parameters
        ----------
        sample:
            A raw, unsanitized ``SampleResult`` from the database layer.

        Returns
        -------
        SanitizationResult
            An immutable pair of the sanitized sample and its audit report.

        Raises
        ------
        TypeError
            If ``sample`` is not a ``SampleResult``.
        SanitizationOrchestratorError
            If any bounded processing limit is exceeded, if a required pseudonymization key is
            missing, or if any internal step cannot complete safely.
        """
        if not isinstance(sample, SampleResult):
            raise TypeError("sample must be a SampleResult")

        _validate_sample_shape(sample, self.config)

        failed = False
        try:
            return self._orchestrate(sample)
        except SanitizationOrchestratorError:
            raise
        except (
            PIIDetectionError,
            SecretDetectionError,
            SanitizationTransformError,
        ) as exc:
            _logger.debug("Sanitization component failed: %s", type(exc).__name__)
            failed = True
        except Exception:  # noqa: BLE001 — raw driver objects must fail closed without leaking.
            failed = True

        if failed:
            raise _safe_error()

        # Unreachable but defensive
        raise _safe_error()  # pragma: no cover

    def _orchestrate(self, sample: SampleResult) -> SanitizationResult:
        """Inner implementation — all exceptions propagate; caller wraps them."""
        policy = self.config.policy
        transformer = SanitizationTransformer(self.config.transform_config)

        secret_detector = SecretCredentialDetector(config=self.config.secret_config)
        pii_detector = PIIDetector(config=self.config.pii_config)

        secret_result = secret_detector.detect(sample)
        pii_result = pii_detector.detect(sample)

        merged_by_col = _merge_classifications(secret_result, pii_result, policy=policy)

        decisions = _resolve_decisions(
            sample=sample,
            merged_by_col=merged_by_col,
            policy=policy,
            allowlist=self.config.non_sensitive_allowlist,
        )

        report = _build_report(
            total_fields=len(sample.columns),
            policy_version=policy.policy_version,
            decisions=decisions,
        )

        if (
            report.pseudonymized_fields > 0
            and self.config.transform_config.pseudonymization_key is None
        ):
            raise _safe_error()

        kept_columns = tuple(
            col for col in sample.columns if decisions[col].action is not SanitizationAction.DROP
        )

        sanitized_rows = _transform_rows(
            sample=sample,
            kept_columns=kept_columns,
            decisions=decisions,
            transformer=transformer,
        )

        sanitized_sample = SanitizedSample(
            schema_name=sample.schema_name,
            table_name=sample.table_name,
            columns=kept_columns,
            rows=sanitized_rows,
            row_count=len(sanitized_rows),
            truncated=sample.truncated,
            policy_version=policy.policy_version,
        )

        return SanitizationResult(sample=sanitized_sample, report=report)
