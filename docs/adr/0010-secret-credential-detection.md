# ADR 0010: Secret and credential detection

- Status: Accepted
- Date: 2026-10-14
- Scope: Phase 3B - Secret and credential detection

## Context

Phase 3A fixed the security contracts and the fail-closed `SanitizationPolicy` (ADR 0009) but
performed no detection. Raw `SampleResult` rows crossing the MCP boundary are trusted but
**unsanitized** and must be classified before the policy can act on them (ADR 0001, decision 5).
Phase 3B adds the first concrete detector: a deterministic classifier that scans raw samples for
secrets and credentials and emits safe, field-level metadata only. It must run without a live
database, without an LLM, and without ever surfacing matched material.

## Decision

1. **Deterministic, no-LLM detector.** `SecretCredentialDetector.detect` is a pure function of its
   input `SampleResult` and an immutable `SecretDetectionConfig`. It makes no network, database,
   MCP, or model calls, and no entropy-based or probabilistic inference. Identical input always
   yields identical output.

2. **Input is a raw `SampleResult`.** The detector reads only `schema_name`, `table_name`,
   `columns`, and the raw `rows` of an unmodified `SampleResult`. It performs no transformation and
   does not mutate the sample.

3. **Output is safe field-level metadata only.** The return type `SecretDetectionResult` carries a
   detector version, a tuple of `FieldClassification` (schema/table/column, sensitivity,
   confidence, detector), and non-negative scan counts. It contains **no** raw cell value, matched
   substring, or snippet, and `repr`/`model_dump` never echo row contents.

4. **No match is not `non_sensitive`.** An unclassified field is simply absent from the result; the
   detector never emits `SensitivityClass.NON_SENSITIVE`. Absence means "this detector found no
   secret or credential signal," which is not a positive safety verdict.

5. **Phase 3B emits only `credential`, `secret`, and `unknown`.** `FieldClassification` results are
   restricted to those three values. `pii` (Phase 3C) and `non_sensitive` are out of scope for this
   detector and are rejected by the result's validation.

6. **Precedence: `credential` > `secret` > `unknown`.** When multiple signals hit one column, the
   strongest wins, ordered first by sensitivity rank (`credential`, then `secret`, then `unknown`),
   then by confidence, then by detector. Exactly one finding is emitted per source column, in
   source-column order.

7. **Conservative column and nested-key matching.** Names (column headers and nested mapping keys)
   are tokenized on camelCase/snake/kebab boundaries and matched against a small explicit set of
   credential tokens and token pairs. Matching is intentionally narrow so that look-alikes
   (`secretary_name`, bare `key`, `salt`, `client_id`) are **not** classified.

8. **High-confidence value-pattern families.** String and decoded-binary values are matched against
   a bounded set of conservative patterns: PEM private-key headers, `Bearer`/`Basic`
   authorization headers, JWT-like structure, URI user-info passwords, and key/value assignments.
   Each is a fixed, bounded regular expression or a bounded parse; there is no entropy-only or
   threshold-based detection.

9. **Bounded scanning.** Text and binary values longer than the configured character/byte limits,
   and containers beyond the configured depth, fail closed to `unknown` rather than being scanned
   unbounded.

10. **Binary handling fails closed.** `bytes`/`bytearray`/`memoryview` are decoded strictly as
    UTF-8; oversized or non-decodable values are classified `unknown`. Decoded text is then treated
    like any other bounded string.

11. **Unsupported and uninspectable values are `unknown`.** Arbitrary driver or database objects,
    unknown scalars, non-string mapping keys, and any value that raises during inspection are
    classified `unknown` (fail-closed). The detector never calls `str()`/`repr()` on an
    uninspectable object.

12. **Per-cell depth and element limits.** Each cell's nested containers are bounded by
    `max_container_depth` and a per-cell `max_container_elements`; exceeding either fails that cell
    closed to `unknown`.

13. **Sample-wide `max_cells`.** A sample whose total cell count exceeds `max_cells` fails closed
    with `SecretDetectionError` before any value is inspected.

14. **Sample-wide `max_total_container_elements`.** A single counter is shared across every cell in
    one `detect` call and bounds the total number of container elements scanned for the whole
    sample. Scalars and name matching do not consume this quota.

15. **Global overflow fails closed with no partial result.** Exceeding the sample-wide element
    budget raises `SecretDetectionError` carrying only a fixed, low-information message. The
    exception aborts the whole scan, so no partial classifications are returned and no raw value or
    snippet appears in the error.

16. **No redaction, masking, or pseudonymization.** Phase 3B classifies only. It performs no
    transformation and does not construct a `SanitizedSample`; that is a later phase.

## Consequences

- The policy now has a deterministic, fail-closed source of `secret`/`credential`/`unknown`
  classifications to act on, with every emitted field bounded and leak-free.
- Because no match is not a safe verdict and unknowns are emitted, downstream must still treat
  unclassified and `unknown` fields as unapproved for LLM exposure until Phase 3A/3F rules are
  applied to them.
- Bounded scanning (per-cell and sample-wide limits) makes the detector's cost and memory
  predictable and resistant to pathological inputs.

## Next phase

Phase 3C - PII detection. A second deterministic detector will classify personal data, reusing the
same bounded, metadata-only, fail-closed shape established here.
