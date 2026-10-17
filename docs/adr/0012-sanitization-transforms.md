# ADR 0012: Sanitization transforms

- Status: Accepted
- Date: 2026-10-17
- Scope: Phase 3D - value-level sanitization transforms

## Context

Phase 3A fixed the fail-closed `SanitizationPolicy` and the `SanitizationAction`/`SanitizedSample`
contracts (ADR 0009): a `pii` field resolves to `pseudonymize`, a `secret`/`credential`/`unknown`
field resolves to `redact`. Phase 3B and 3C added the two deterministic detectors
(`SecretCredentialDetector`, ADR 0010, and `PIIDetector`, ADR 0011) that classify raw fields. The
policy therefore already produces a complete, deterministic classification-to-action decision for
every field, and the `SanitizedSample` boundary that a transformed row must satisfy is already
validated. What is missing is the deterministic code that executes those per-value actions: no
module yet turns a raw cell into an allow / redact / mask / pseudonymize / drop result. Phase 3D
adds that primitive. It is the single-value half of the transform step; aggregation into a
`SanitizedSample` is Phase 3E and leakage validation is Phase 3F.

## Decision

1. **Value-level, one action at a time.** `SanitizationTransformer.transform(value, decision)`
   takes one raw value and one already-resolved `SanitizationDecision` and applies exactly
   `decision.action`. It does not decide sensitivity, run a detector, merge findings, build a
   `SanitizedSample`, or validate leakage. It executes the action the policy chose for a single
   cell, and nothing else.

2. **Deterministic, no-LLM, no-entropy, no side effects.** The transform is a pure function of its
   input value and its `SanitizationTransformConfig`. It makes no network, database, MCP, or model
   calls and performs no probabilistic inference. Identical input always yields identical output.

3. **Pseudonymization is keyed HMAC over canonical bytes.** `pseudonymize` computes
   `HMAC-SHA256(key, canonical(value))` and returns
   `psn_v1_` + URL-safe base64 (no padding) of the 32-byte digest. There is no stored mapping and no
   database lookup; identical values map to identical tokens, and a different key maps them
   elsewhere. The HMAC key is **not** hardcoded: it is supplied through
   `SanitizationTransformConfig.pseudonymization_key` and is required only for `pseudonymize`
   (never for `allow`, `redact`, `mask`, or `drop`). A versioned domain separator is mixed into the
   message, so a change of key or algorithm changes every token (a "salt" effect), and the key is
   not required for the other four actions.

4. **The pseudonymization key is a `SecretStr`, 32-4096 bytes.** The config rejects any non-text key
   (`bytes`/`bytearray` are rejected rather than coerced), and enforces a 32-byte minimum and a
   4096-byte maximum. The key is never shown in `repr`, `model_dump`, or `model_dump_json`, and it
   never appears in any error or exception.

5. **Canonical, collision-safe value encoding.** The HMAC input is a canonical byte encoding of the
   value that is explicit about type, so `1` / `"1"` / `True` / `1.0` / `Decimal("1")` / `b"1"` never
   collide. The encoding uses one byte tag per supported type plus length framing, and **never calls
   `str()` or `repr()`** on the value. Supported scalar types are `None`, `bool`, `int`, finite
   `float`, `str`, finite `Decimal`, `date`, `datetime`, `time`, `UUID`, and `bytes`-family values.
   `float` values are encoded from `float.hex()` and `Decimal` from its exact string form.

6. **Nested containers are canonicalized too.** `list`, `tuple`, and `Mapping` values are supported:
   each is length-framed and each element is canonicalized recursively. `Mapping` keys must be
   `str` (any other key type fails closed) and entries are ordered by key so key order never changes
   the token. The traversal is bounded by the config's `max_container_depth` and a shared
   `max_container_elements` budget; exceeding either fails closed.

7. **The pseudonym is length- and type-independent.** Because the output is always the fixed
   `psn_v1_` prefix plus a fixed-length base64 of a 32-byte digest, the token reveals nothing about
   the original value's length, type, or shape. A `None` value pseudonymizes to `None` (a genuine
   null stays a null).

8. **`redact` and `mask` are fixed markers that reveal no structure.** Both return a single fixed
   marker (`[REDACTED]` / `[MASKED]`) regardless of the original value's length, type, or shape, and
   return `None` for a `None` input. They therefore never leak length or type.

9. **`allow` checks the scalar domain, then normalizes.** `allow` only accepts values in the
   `SanitizedValue` domain (`None`, `bool`, `int`, finite `float`, `str`) or a value that can be
   deterministically normalized to it (`Decimal`, `date`/`datetime`/`time`, `UUID`, and UTF-8-decodable
   bounded bytes). Non-finite floats, `NaN`/`Infinity` `Decimal`s, arbitrary driver objects, and
   containers are rejected (fail closed).

10. **`drop` is distinguishable from a genuine `None`.** A `drop` result sets `dropped=True` and
    carries no value. A genuine `None` produced by `allow`/`redact`/`mask`/`pseudonymize` has
    `dropped=False`. This lets Phase 3E omit a dropped field without confusing it with a legitimate
    null cell.

11. **Fail closed, leak-free.** The transform bounds each value by its own `SanitizationTransformConfig`
    (per-value text/binary/depth/element limits, aligning with the Phase 3B/3C detector limits). An
    oversized or unsupported value raises `SanitizationTransformError` carrying only a fixed,
    low-information message. The error and the public result never contain the raw value or a
    substring of it; the result hides its value from `repr` (`model_dump` carries it, because that is
    the transform payload). No generic `str()`/`repr()` is ever called on an arbitrary object.

12. **The result is metadata-aware.** `SanitizationTransformResult` is an immutable, frozen
    `extra="forbid"` model carrying `action`, `value` (the transformed `SanitizedValue`), `dropped`,
    and a `transformer_version`. A model validator enforces the action/`dropped`/value
    consistency invariants (drop ⇔ dropped with no value; redact/mask require a marker; an allowed
    float must be finite).

13. **Public API.** The module exports `SanitizationTransformer`, `SanitizationTransformConfig`,
    `SanitizationTransformResult`, and `SanitizationTransformError` through the
    `automatic_dataset_generation.security` package.

14. **No aggregation and no leakage validation.** Phase 3D transforms one value. It does not run the
    detectors, does not merge the two detection results, does not construct a `SanitizedSample`, and
    does not validate that a completed sample is leakage-free; those are Phase 3E and 3F.

## Consequences

- The policy's `pseudonymize`/`redact`/`mask`/`drop` decisions now have a deterministic, fail-closed
  executor, so a classified field can be turned into a `SanitizedValue`-domain cell.
- Pseudonymized data is non-reversible without the key and is length- and type-independent, and the
  key is operator-supplied rather than baked into the package. Because there is no stored mapping,
  de-pseudonymization is out of scope (and is not a goal of LLM-eligibility).
- Because a value's action comes from its classification, an `allow`d field can still be dropped or
  redacted later: this phase only guarantees it does not itself transform `allow`ed in-domain values
  into something else. `redact` and `mask` return the same fixed marker shape (different literal
  text), so they do not reveal length or type.
- Bounded scanning (per-value limits) and the leak-free error make the transform's cost predictable
  and resistant to pathological inputs, consistent with Phase 3B/3C.

## Next phase

Phase 3E - sanitization orchestration. It will run the Phase 3B and 3C detectors over a raw
`SampleResult`, merge their field-level results, resolve each field's action through the policy,
apply `SanitizationTransformer` per cell, and construct the `SanitizedSample` boundary.
