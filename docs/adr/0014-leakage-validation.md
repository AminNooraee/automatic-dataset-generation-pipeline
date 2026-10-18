# ADR 0014: Leakage validation

- Status: Accepted
- Date: 2026-10-18
- Scope: Phase 3F - Leakage validation

## Context

Phase 3A defined the immutable security contracts and `SanitizationPolicy` (ADR 0009). Phase 3B implemented
`SecretCredentialDetector` (ADR 0010). Phase 3C implemented `PIIDetector` (ADR 0011). Phase 3D implemented
`SanitizationTransformer` (ADR 0012). Phase 3E implemented `SanitizationOrchestrator` (ADR 0013) to coordinate
detector execution, classification merging, policy action resolution, cell transformations, and report generation.

However, Phase 3E produces a `SanitizedSample` based on field-level classifications and policy rules. It does
**not** guarantee that the sample is leakage-free or safe for LLM consumption:
- Whole-value detectors may not flag free-text fields where sensitive substrings (e.g., an email address,
  bearer token, or connection string) are embedded within otherwise ordinary narrative text.
- Malicious or corrupted objects may bypass standard constructors via Pydantic's `model_construct` or
  unchecked `model_copy(update=...)`, resulting in shape mismatches, non-scalar values, NaN/infinite floats,
  or forged metadata.
- Absence of detector findings or allowlist inclusion does not prove that a field contains no sensitive data.

Phase 3F introduces an independent, deterministic leakage validation layer that inspects the sanitized output
prior to any LLM prompt construction or agent consumption (Phase 4).

## Decision

1. **Dedicated leakage validation engine (`LeakageValidator`).**
   Phase 3F implements `LeakageValidator`, an independent security gate that examines a Phase 3E
   `SanitizationResult` or `SanitizedSample` (with optional `SanitizationReport`) against strict structural,
   resource, and residual leakage criteria.

2. **Strict structural and boundary revalidation.**
   The validator never assumes that constructing a `SanitizedSample` proves sanitization or provenance:
   - Revalidates actual row count (`len(sample.rows) == sample.row_count`).
   - Verifies every row is a tuple whose length matches the declared column count (`len(row) == len(sample.columns)`).
   - Revalidates that all column names are non-empty, unique, contain no NUL bytes, and obey length limits.
   - Revalidates that metadata (`schema_name`, `table_name`, `policy_version`) is non-empty, contains no NUL bytes,
     and obeys identifier limits.
   - Verifies that all cell values are strictly members of the allowed scalar domain (`None`, `bool`, `int`,
     `float`, `str`). Rejects unsupported types (`bytes`, `dict`, `list`, `Decimal`, `UUID`, etc.).
   - Verifies that all floating-point numbers are strictly finite (`math.isfinite(val)`). Rejects `NaN`, `inf`,
     and `-inf`.
   - Rejects objects forged or corrupted via `model_construct` or `model_copy(update=...)`.
   - Strictly validates validator configuration instances via `_validate_config()`, rejecting non-instance types,
     out-of-bounds dimension limits, and type mismatches.

3. **Independent bounded resource limits and upfront enforcement.**
   The validator enforces independent dimensions and character budgets on actual data:
   - `max_fields`: Maximum columns (default 1,000; absolute maximum 10,000).
   - `max_rows`: Maximum rows (default 10,000; absolute maximum 1,000,000).
   - `max_cells`: Maximum cells (actual_rows * actual_columns, default 100,000; absolute maximum 1,000,000).
   - `max_text_chars`: Maximum character length of any individual cell string (default 16,384; maximum 1,000,000).
   - `max_total_text_chars`: Maximum cumulative character budget across all cells in the sample (default 1,000,000;
     maximum 10,000,000).
   - Dimension limits (`max_fields`, `max_rows`, `max_cells`) are validated upfront in `_validate_structure()`
     before any row traversal or cell scanning begins. Samples violating structural limits are aborted immediately,
     preventing resource exhaustion or bypasses.

4. **Consistency verification with Phase 3E report metadata.**
   When a `SanitizationReport` is provided (e.g., via `SanitizationResult`):
   - Verifies that `report.policy_version == sample.policy_version`.
   - Verifies that retained columns match report field counts: `len(sample.columns) == report.total_fields - report.dropped_fields`.
   - Revalidates report count consistency: non-negative counts, `classified_fields == total_fields`, sum of actions
     (`redacted + masked + pseudonymized + dropped + allowed`) equals `classified_fields`, `unknown_fields <= classified_fields`,
     and `dropped_fields <= total_fields`.

5. **Sanitization marker awareness.**
   The validator distinguishes legitimate transformation outputs from residual leakage:
   - `[REDACTED]`: Recognized redaction marker; skipped during residual leakage scanning.
   - `[MASKED]`: Recognized masking marker; skipped during residual leakage scanning.
   - `psn_v1_[A-Za-z0-9_-]{43}`: Well-formed pseudonym token; recognized as valid transformation output.
   - `None`: Genuine null values; accepted without leakage flags.

6. **Deterministic linear candidate scanning for database connection strings.**
   To eliminate quadratic regex execution and catastrophic backtracking on long non-URI inputs:
   - Unrestricted regex searches are replaced with a deterministic, linear O(N) candidate scanner
     (`_has_connection_string_with_password()`).
   - The scanner advances strictly forward using `text.find("://", pos)` and inspects all URI candidates in text.
   - Schemes are bounded to 32 characters (`_URI_SCHEME_RE`), and authorities are bounded to 512 characters.
   - All URI candidates in the text are evaluated; an unredacted password in a later candidate is never masked
     by a preceding redacted URI.

7. **Bounded canonicalization and metadata scanning.**
   - Applies single-pass bounded canonicalization (`_canonicalize_text()`) before inspection:
     strips zero-width/formatting Unicode characters (`_UNICODE_FORMAT_CHARS_RE`) and performs single-pass
     percent-decoding (`urllib.parse.unquote`). Both raw and canonicalized texts are inspected.
   - Residual leakage patterns detected include embedded emails, international phones, payment cards (Luhn-valid),
     IBANs (mod-97 valid), US SSNs, Bearer/Basic credentials, JWTs, private key PEM headers, and credential/secret
     assignments.
   - Metadata strings (`schema_name`, `table_name`, and column names in `columns`) are scanned in both raw and
     canonicalized forms for embedded secrets and sensitive assignments, while preserving valid ordinary identifiers
     (e.g., `"email"`, `"password"`, `"api_key"`) without false positives.

8. **Fail-closed decision boundary, snapshot isolation, and threat model.**
   - Explicit outcome: Validation produces an accepted outcome only when all structural, limit, consistency,
     and leakage checks pass.
   - Atomic failure: On any violation or detected leakage, `sample` is set to `None`. No partial or unvalidated
     sample escapes.
   - Threat Model & Boundary: `ValidatedSample` provides compile-time and type-level assurance and protection
     against accidental pipeline miswiring in normal supported application flows. Arbitrary in-process Python
     code running within the same interpreter (via `object.__new__`, `object.__setattr__`, or reflection) is
     outside the enforceable security boundary of this class in standard Python.
   - Snapshot Isolation: Upon validation, `ValidatedSample` takes an independent deep snapshot of columns and
     rows (`_snapshot_rows`), preventing post-validation mutations or aliasing of caller-owned objects from
     affecting validated state.
   - Phase 4 Obligation: Phase 4 agent orchestration consumes `ValidatedSample`, and must revalidate data at the
     final prompt-construction boundary immediately before LLM consumption.

9. **Safe reporting and detached exceptions.**
   - `LeakageValidationReport` contains only bounded, non-sensitive audit metadata: outcome, validator version,
     policy version, checked counts, and safe lowercase alphanumeric reason codes (e.g., `residual_email`,
     `residual_jwt`). Raw values, matched substrings, and secret tokens are strictly excluded.
   - Public exceptions (`LeakageValidationError`) are raised after leaving internal exception handlers, and both
     `__context__` and `__cause__` are explicitly stripped (`None`). This prevents sensitive exception messages
     or injected secrets from leaking through standard exception chains or tracebacks.
   - `ValidatedSample` payloads and their `to_sanitized_sample().rows` representations contain cell values and are
     **not** log-safe. Diagnostic logging must use `LeakageValidationReport` or default `repr()` representations
     (which omit payload rows).

10. **Security limitations and non-guarantees.**
    - Pattern-based vs. Semantic Privacy: The validator provides deterministic pattern-based verification. It does
      not provide differential privacy, k-anonymity, or natural language semantic inference against context-dependent
      disclosures or unstructured names/addresses that lack checksums.
    - Provenance: Syntactically valid pseudonym tokens are recognized, but cryptographic verification of the HMAC
      token would require raw inputs and the secret key, which are unavailable at this boundary.

## Consequences

- The pipeline now has an independent, deterministic security gate between data transformation (Phase 3E)
  and prompt formatting (Phase 4).
- Downstream Phase 4 code can enforce type safety by accepting only `ValidatedSample`.
- Unvalidated `SanitizedSample` instances, boolean flags, or manually created mocks cannot silently bypass
  validation.
- Residual sensitive material embedded in free text or allowlisted columns is reliably caught before prompt
  construction.

## Next phase

Phase 4 - Agent orchestration. The agent layer will consume `ValidatedSample` objects to formulate LLM prompts
and orchestrate dataset planning, revalidating contracts at the prompt-construction boundary.
