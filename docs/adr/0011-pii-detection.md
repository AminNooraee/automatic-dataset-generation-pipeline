# ADR 0011: PII detection

- Status: Accepted
- Date: 2026-10-14
- Scope: Phase 3C - PII detection

## Context

Phase 3A fixed the security contracts and the fail-closed `SanitizationPolicy` (ADR 0009): the
`SensitivityClass.PII` value already exists and the default policy already maps `pii -> pseudonymize`.
Phase 3B added the first concrete detector, the deterministic `SecretCredentialDetector` (ADR 0010),
which emits `credential`/`secret`/`unknown` and **rejects** `pii` in its result validation, deferring
personal-data classification to Phase 3C. The policy therefore still has no deterministic source of
`pii` classifications for the PII fields that are the most common LLM-exposure risk (names, contact
detail, and identifiers). Phase 3C adds that second detector.

## Decision

1. **Deterministic, no-LLM, no-entropy detector.** `PIIDetector.detect` is a pure function of its input
   `SampleResult` and an immutable `PIIDetectionConfig`. It makes no network, database, MCP, or model
   calls and performs no entropy-based or probabilistic inference. Identical input always yields
   identical output. It mirrors the shape of the Phase 3B detector.

2. **Input is a raw `SampleResult`.** The detector reads only `schema_name`, `table_name`, `columns`,
   and the raw `rows` of an unmodified `SampleResult`. It performs no transformation and does not
   mutate the sample.

3. **Output is safe field-level metadata only.** The return type `PIIDetectionResult` carries a
   detector version, a tuple of `FieldClassification` (schema/table/column, sensitivity, confidence,
   detector), and non-negative scan counts. It contains **no** raw cell value, matched substring, or
   snippet, and `repr`/`model_dump` never echo row contents.

4. **No match is not `non_sensitive`.** An unclassified field is simply absent from the result; the
   detector never emits `SensitivityClass.NON_SENSITIVE`. Absence means "this detector found no PII
   signal," which is not a positive safety verdict.

5. **Phase 3C emits only `pii` and `unknown`.** `FieldClassification` results are restricted to those
   two values. `credential`, `secret`, and `non_sensitive` are out of scope for this detector and are
   rejected by the result's validation. (The inverse of ADR 0010 decision 5.)

6. **Precedence: `pii` > `unknown`.** When multiple signals hit one column, the strongest wins, ordered
   first by sensitivity rank (`pii`, then `unknown`), then by confidence, then by detector. Exactly one
   finding is emitted per source column, in source-column order.

7. **Conservative, tokenized name/metadata matching.** Names (column headers and nested mapping keys)
   are tokenized on camelCase/snake/kebab boundaries and matched against a small explicit set of PII
   single tokens and adjacent token pairs, grouped by category: email; phone; person name; birth date;
   postal address; personal identifiers (`user_id`, `customer_id`, `patient_id`, `national_id`,
   `passport_number`, …); financial identifiers; and IP/MAC metadata. Matching is intentionally narrow,
   so look-alikes (bare `name`, `order_id`, `product_id`, `secretary_name`) are **not** classified.
   Ambiguous tokens (`name`, `id`, `number`, `address`) are matched only in a person/entity context.
   This is metadata/name detection only.

8. **High-confidence value detection for a bounded set.** String and decoded-binary values are matched
   against a conservative set of **exact, whole-value** patterns, each a fixed bounded regular
   expression or a bounded standard-library parse — no entropy, no threshold, and no free-text
   scanning: email addresses; international phone numbers with an explicit `+` country code; IPv4 and
   IPv6 addresses via Python's `ipaddress`; canonical MAC addresses; payment-card numbers only when
   they form a standalone card number (13-19 digits after removing approved separators) and pass the
   Luhn checksum; and IBANs only when MOD-97-valid. There is no card-brand prefix catalog and no
   arbitrary long-number detection: conservativeness comes from the standalone whole-value match, the
   13-19 digit bound, approved separators only, and Luhn validation.

9. **No free-text value detection for the hard categories.** Person names, postal addresses, dates of
   birth, and SSN/national-ID/passport numbers across countries are detected **by name/metadata only**,
   never by scanning free-text values. These are too context- and locale-dependent for a conservative
   deterministic value detector, and value-level false positives are deliberately avoided.

10. **Bounded scanning.** Text and binary values longer than the configured character/byte limits, and
    containers beyond the configured depth, fail closed to `unknown` rather than being scanned
    unbounded. The limits mirror the Phase 3B detector.

11. **Binary handling fails closed.** `bytes`/`bytearray`/`memoryview` are decoded strictly as UTF-8;
    oversized or non-decodable values are classified `unknown`. Decoded text is then treated like any
    other bounded string.

12. **Unsupported and uninspectable values are `unknown`.** Arbitrary driver or database objects,
    unknown scalars, non-string mapping keys, and any value that raises during inspection are
    classified `unknown` (fail-closed). The detector never calls `str()`/`repr()` on an uninspectable
    object.

13. **Per-cell depth and element limits.** Each cell's nested containers are bounded by
    `max_container_depth` and a per-cell `max_container_elements`; exceeding either fails that cell
    closed to `unknown`.

14. **Sample-wide `max_cells`.** A sample whose total cell count exceeds `max_cells` fails closed with
    `PIIDetectionError` before any value is inspected.

15. **Sample-wide `max_total_container_elements`.** A single counter is shared across every cell in one
    `detect` call and bounds the total number of container elements scanned for the whole sample.
    Scalars and name matching do not consume this quota.

16. **Global overflow fails closed with no partial result.** Exceeding the sample-wide element budget
    raises `PIIDetectionError` carrying only a fixed, low-information message. The exception aborts the
    whole scan, so no partial classifications are returned and no raw value or snippet appears in the
    error.

17. **No redaction, masking, or pseudonymization.** Phase 3C classifies only. It performs no
    transformation and does not construct a `SanitizedSample`; that is a later phase.

## Consequences

- The policy now has a deterministic, fail-closed source of `pii` classifications (in addition to the
  `secret`/`credential`/`unknown` source from Phase 3B), with every emitted field bounded and
  leak-free. `pii` flows to `pseudonymize` under the default policy.
- Because no match is not a safe verdict and unknowns are emitted, downstream must still treat
  unclassified and `unknown` fields as unapproved for LLM exposure until the Phase 3A/3F rules are
  applied to them.
- Value detection is deliberately narrow (exact, whole-value, and checksum-validated where a checksum
  exists), trading recall for a low false-positive rate, consistent with the conservative,
  deterministic posture of Phase 3B.
- Bounded scanning (per-cell and sample-wide limits) makes the detector's cost and memory predictable
  and resistant to pathological inputs.

## Next phase

Phase 3D - sanitization transforms. Deterministic transformations will implement the `SanitizationAction`
decisions (redact, mask, pseudonymize, drop) produced by the policy from the Phase 3B and 3C
classifications, constructing the `SanitizedSample` boundary.
