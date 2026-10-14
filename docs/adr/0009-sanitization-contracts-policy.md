# ADR 0009: Sanitization contracts and policy

- Status: Accepted
- Date: 2026-10-14
- Scope: Phase 3A - Sanitization contracts and policy

## Context

Phases 2C through 2I delivered read-only database adapters and a safe MCP boundary. Their
`sample_rows` output crosses the MCP boundary as trusted raw `SampleResult` rows that are
**not** sanitized and must not reach an LLM (ADR 0008). Phase 3 introduces a deterministic security
and sanitization layer that processes every `sample_rows` result before any database-derived content
may reach a prompt (ADR 0001, decision 5).

Phase 3A is the first bounded step of Phase 3. It defines and validates the security contracts and
the classification-to-action policy. It performs **no** sanitization, no detection, and no
transformation itself; it fixes the data boundaries and invariants that later phases build on.

## Decision

1. **Scope: contracts and policy only.** Phase 3A defines the immutable domain contracts and
   `SanitizationPolicy`, and nothing else. There are no detectors, transforms, or pseudonymization
   algorithms in this phase. `SanitizationPolicy` only maps a classification to an action.

2. **`SampleResult` stays raw.** The Phase 2 `SampleResult` is unchanged: it is trusted raw,
   **unsanitized** data. It may never be sent to a prompt, log, telemetry, or artifact.

3. **`SanitizedSample` is a distinct boundary contract.** `SanitizedSample` is the separate,
   LLM-eligible data contract that a later sanitizer constructs. Constructing a `SanitizedSample`
   **does not** by itself prove the data is leakage-free; it only proves the data matches the
   declared, JSON-safe scalar domain and shape.

4. **Leakage validation is a separate required step.** Proving a `SanitizedSample` is leakage-free
   remains required before any LLM exposure and is deliberately deferred to Phase 3F. Phase 3A
   validation is necessary but not sufficient for safe LLM use.

5. **`SensitivityClass`.** A broad, stable classification of a field: `non_sensitive`, `pii`,
   `secret`, `credential`, and `unknown`. These are labels for a classification, not secret
   material.

6. **`SanitizationAction`.** A transformation decision to be implemented in a later phase:
   `allow`, `redact`, `mask`, `pseudonymize`, and `drop`. Phase 3A defines the action vocabulary
   but implements none of the transformations.

7. **Fail-closed `UNKNOWN`.** Data classified `unknown` is treated as sensitive. The policy may not
   map `pii`, `secret`, `credential`, or `unknown` to `allow`, and a `SanitizationDecision` may not
   pair any non-`non_sensitive` classification with `allow`. Missing or ambiguous data is never
   allowed through.

8. **Default policy.**

   | Sensitivity   | Action       |
   | ------------- | ------------ |
   | `non_sensitive` | `allow`    |
   | `pii`         | `pseudonymize` |
   | `secret`      | `redact`     |
   | `credential`  | `redact`     |
   | `unknown`     | `redact`     |

9. **Immutable policy mapping.** `SanitizationPolicy.actions` is a complete, fail-closed mapping of
   every `SensitivityClass` to a `SanitizationAction`. It is typed as
   `Mapping[SensitivityClass, SanitizationAction]`, not a mutable `dict`. At construction the
   mapping is validated for completeness and fail-closed behavior, then stored as a defensive
   `MappingProxyType` snapshot of a copy of the caller's mapping. External mutation of the
   caller's mapping cannot change policy behavior, and the snapshot itself is immutable. The
   public type contract is therefore `Mapping`, and the runtime storage is an immutable mapping.

10. **No secret material in the policy.** The policy stores only the version label and the
    classification-to-action mapping. It contains no key, salt, token, password, or credential
    material and nothing from which such material could be derived.

11. **Metadata-only identity and classification.** `FieldReference` (schema/table/column) and
    `FieldClassification` (field, sensitivity, confidence, detector) contain metadata only. Neither
    stores a raw or matched cell value.

12. **Metadata-only decision.** `SanitizationDecision` carries the field, sensitivity, resolved
    action, policy version, and a reason code. It carries no transformation material and no raw
    value.

13. **`SanitizedValue` domain.** `SanitizedSample.rows` permit only `None`, `bool`, `int`, finite
    `float`, and `str`. Arbitrary driver or database objects (bytes, `Decimal`, `memoryview`,
    unknown objects) are rejected, and non-finite floats are rejected.

14. **Rows hidden from repr.** `SanitizedSample.rows` is excluded from `repr` as defense in depth
    so that logged or error-surfaced samples do not echo row contents.

15. **`SanitizationReport` is counts only.** The audit report carries the policy version and
    non-negative, mutually consistent field counts only. It carries no field names, values, or
    matched substrings.

## Consequences

- A later sanitization phase has a fixed, immutable, and fail-closed contract to implement
  against, and a policy that cannot be weakened to allow sensitive or unknown data through.
- `SampleResult` remains a distinct, raw, unsanitized contract; crossing into LLM-eligible data
  requires explicit construction of a `SanitizedSample` and, separately, Phase 3F leakage
  validation.
- No sanitization behavior exists yet: detection, transformation, and leakage validation are all
  deferred.

## Next phase

Phase 3B - Secret / credential detection. A deterministic detector will classify fields and mark
raw values as `secret`, `credential`, or other sensitities for the policy to act on. Phase 3A
defines the classification and action vocabulary that detector will emit.
