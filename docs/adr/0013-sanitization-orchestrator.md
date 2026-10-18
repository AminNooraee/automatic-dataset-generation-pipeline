# ADR 0013: Sanitization orchestrator

- Status: Accepted
- Date: 2026-10-18
- Scope: Phase 3E - Sanitization orchestration

## Context

Phase 3A defined the immutable security contracts and the classification-to-action `SanitizationPolicy`
(ADR 0009). Phase 3B implemented `SecretCredentialDetector` (ADR 0010) to classify secrets and
credentials. Phase 3C implemented `PIIDetector` (ADR 0011) to classify personally identifiable
information. Phase 3D implemented `SanitizationTransformer` (ADR 0012) to execute individual cell
transformations deterministically.

However, each preceding phase addressed an isolated component:
- Detectors classify fields independently and return separate `SecretDetectionResult` and `PIIDetectionResult` structures.
- Detectors produce no transformed rows and emit no `SanitizedSample`.
- `SanitizationTransformer` transforms single cell values given pre-resolved decisions, but does not inspect samples, merge findings, or handle column inclusion/omission.

Phase 3E provides the orchestration layer that binds these components into an integrated, fail-closed,
atomic pipeline that takes raw database `SampleResult` rows and produces an immutable `SanitizedSample`
and `SanitizationReport`.

## Decision

1. **Integrated orchestration layer (`SanitizationOrchestrator`).**
   The orchestrator accepts a raw `SampleResult`, validates actual dimensions, runs both
   `SecretCredentialDetector` and `PIIDetector` over the sample, merges field classifications,
   resolves decisions via `SanitizationPolicy`, transforms individual cells using
   `SanitizationTransformer`, filters dropped columns, and packages the result into an immutable
   `SanitizationResult` containing a `SanitizedSample` and `SanitizationReport`.

2. **Fail-closed default for unclassified fields.**
   The absence of detector findings is never treated as proof of non-sensitivity. If neither detector
   flags a field, it defaults to `SensitivityClass.UNKNOWN`. Under the default policy, `UNKNOWN` resolves
   to `SanitizationAction.REDACT`.

3. **Narrow, bounded non-sensitive allowlist.**
   Callers may configure `non_sensitive_allowlist` with column names pre-declared as non-sensitive:
   - Applied **only** when both detectors find no sensitive signal. Any positive detector finding
     (secret, credential, PII, or unknown/uninspectable) unconditionally overrides the allowlist.
   - Iterable inputs are consumed with strict bounds (`_MAX_FIELDS = 10,000` items maximum and
     `_MAX_IDENTIFIER_LENGTH = 128` characters per entry) to prevent hanging on infinite iterators
     or unbounded memory consumption.
   - The allowlist size is enforced to never exceed `max_fields`.

4. **Deterministic, policy-aware merge precedence.**
   When both detectors produce a finding for the same column, findings are merged using a deterministic,
   policy-aware rule that never weakens protection:
   - Compare the protection rank of the actions each classification resolves to under `policy`:
     `DROP` (3) > `REDACT` / `MASK` (2) > `PSEUDONYMIZE` (1) > `ALLOW` (0). The classification yielding
     strictly stronger protection wins.
   - For actions with equal protection rank (e.g., both resolving to `REDACT`), ties are broken by
     sensitivity severity rank: `CREDENTIAL` (4) > `SECRET` (3) > `PII` (2) > `UNKNOWN` (1).
   - If sensitivity severity is also equal, higher confidence wins; the secret detector is preferred
     in case of identical confidence.
   - No finding is ever weakened or discarded due to the absence or lower severity of a finding from the
     other detector.

5. **Mandatory pseudonymization key check.**
   Whenever any column resolves to `SanitizationAction.PSEUDONYMIZE`, a valid 32-4096 byte key is
   strictly required in `transform_config.pseudonymization_key`. This is enforced upfront during
   orchestration even if the sample contains 0 rows or only `None` values. The key is never logged or
   disclosed in string representations.

6. **Clear distinction between dropped columns and genuine `None` values.**
   Columns resolved to `SanitizationAction.DROP` are completely omitted from `SanitizedSample.columns`
   and all row tuples in `SanitizedSample.rows`. Legitimate null values in retained columns remain as
   `None` within their respective cells (`dropped=False`). Dropped fields are counted separately in
   `SanitizationReport.dropped_fields`.

7. **Validated actual dimensions and resource limits.**
   To prevent processing-limit bypasses via `model_construct`, `model_copy(update=...)`, or malformed
   metadata:
   - Row count is verified against actual length: `sample.row_count == len(sample.rows)`.
   - Every row width is strictly verified against declared column count: `len(row) == len(sample.columns)`.
   - Independent bounds enforce `max_fields` (default 1,000, max 10,000), `max_rows` (default 10,000,
     max 1,000,000), and `max_cells` (default 100,000, max 1,000,000). Zero-row samples with excessive
     columns or zero-column samples with excessive rows are rejected upfront.

8. **Detached exceptions and atomic failure without leakage.**
   If any detector, transformer, or validation step fails or encounters an uninspectable/unsupported
   value, the orchestrator raises a safe, low-information `SanitizationOrchestratorError`.
   - The public exception is raised after exiting internal exception handlers, and both `__context__`
     and `__cause__` are explicitly stripped (`None`). This prevents internal exception messages
     (which may contain injected or matched secrets) from leaking through exception chains or standard
     formatted tracebacks.
   - Note: Diagnostic tools that inspect raw execution frame locals of failing components are outside
     this guarantee, as they capture caller/callee stack frame environments directly.
   - No partially sanitized output is ever returned.

9. **Accurate data exposure and logging guarantees.**
   - Detected sensitive values (credentials, secrets, PII) and unknown values are never exposed raw
     in results without policy protection.
   - Explicitly approved non-sensitive values (via `non_sensitive_allowlist`) may remain in
     `SanitizationResult.sample` in normalized scalar domain form.
   - Payload serialization via `model_dump()` or `model_dump_json()` serializes cell values and is
     **not** log-safe. Diagnostic logging must rely on `SanitizationReport` or default `repr()`
     representations (which exclude row payloads and secret keys).

10. **Isolation and zero external dependencies.**
    The orchestrator is pure Python business logic. It makes no database connections, no network or MCP
    calls, and no LLM queries.

11. **Sanitization is not leakage validation (Phase 3F remains mandatory).**
    `SanitizedSample` produced by Phase 3E conforms to data contracts and executes policy transformations,
    but does **not** prove absence of leakage or semantic data exposure. Phase 3F leakage validation
    remains mandatory before any database sample reaches an LLM prompt.

## Consequences

- The pipeline now has an automated, end-to-end field sanitization engine that coordinates detection,
  decision, and transformation.
- The fail-closed design guarantees that unknown fields, malformed metadata, and detection errors can
  never result in raw data exposure or resource exhaustion.
- Exception chains and audit reports expose zero sensitive material.
- Pseudonymization preserves deterministic linkage across rows while preventing reversal without the key.
- The output `SanitizationResult` contains complete lineage and audit counts via `SanitizationReport`.

## Next phase

Phase 3F - Leakage validation. A dedicated verification phase will inspect completed `SanitizedSample`
payloads against residual sensitive patterns, heuristics, and constraints before data is eligible for
LLM prompt construction.
