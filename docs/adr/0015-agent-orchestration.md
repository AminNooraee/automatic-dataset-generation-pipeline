# ADR 0015: Agent orchestration layer

- Status: Accepted
- Date: 2026-10-19
- Scope: Phase 4 — Agent orchestration

## Context

Phase 1 implemented asynchronous database adapters across six relational engines (ADR 0001–0007).
Phase 2I introduced `DatabaseToolService` and FastMCP tools (ADR 0008), which provided raw database access for trusted components.
Phase 3A–3F implemented the multi-layer database sanitization and leakage validation pipeline (ADR 0009–0014), terminating in `LeakageValidator` which certifies samples as `ValidatedSample`.

ADR 0014 explicitly mandated that prior to exposing any database-derived content to an LLM, the system must enforce an independent revalidation at the final prompt-construction boundary.
Phase 4 requires building a secure, bounded, testable PydanticAI agent orchestration layer connected via an OpenAI-compatible LiteLLM gateway for Qwen.

### Threat Model & Invariants

1. **Untrusted LLM Output and Model Unpredictability:** LLM responses are not assumed to follow structured output schemas identically across all LiteLLM/Qwen deployments. Safe fallback extraction must be provided without compromising security.
2. **Untrusted Database Content and Metadata:** Database records, column names, schema names, and server information are untrusted data and potential prompt injection vectors. They must never be treated as executable instructions or allowed to expand tool permissions or resource budgets.
3. **Confined Raw Database Access:** The Phase 2I raw FastMCP `sample_rows` tool must **never** be registered on or exposed to the LLM agent. All sampling operations must traverse the security pipeline in trusted application code.
4. **Credential Isolation & Zero Leakage:** Connection strings, database passwords, gateway API keys, and Authorization headers must never enter prompts, tool responses, message histories, logs, or exception chains.
5. **Deterministic Boundaries:** Agent construction and import must cause zero network or database I/O. Connections must be constrained to trusted gateway hosts.

## Decision

We implement a clean, isolated orchestration layer under `src/automatic_dataset_generation/orchestration/` structured into five focused modules:

```
src/automatic_dataset_generation/orchestration/
├── contracts.py     # Immutable Pydantic request, response, and safe database view models
├── gateway.py       # OpenAI-compatible LiteLLM provider configuration and endpoint validation
├── secure_tools.py  # Restricted database capability facade and final LLM boundary validator
├── agent.py         # PydanticAI agent factory with exact tool allowlist
├── service.py       # Execution coordination, timeouts, budgets, and fallback handling
└── __init__.py      # Explicit public API exports
```

### 1. Immutable Contracts (`contracts.py`)

All cross-boundary data transfers use frozen Pydantic models:
- **`DatabaseAgentRequest`**: Carries user prompt, optional execution run ID, and context metadata.
- **`DatabaseUnderstandingResponse`**: Structured agent output describing database schema, tables (`TableSummary`), relationships (`DatabaseRelationshipSummary`), fulfillment status (`can_fulfill`), and security notes.
- **Safe Database Views**: `SafeServerInfo`, `SafeTableInfo`, `SafeColumnInfo`, `SafeTableDescription`, `SafeRelationshipInfo`, `SafeRowCountResult`, and `SafeSampleResponse`.
- **Execution State & Metrics**: `AgentExecutionContext` (tracks run ID, audit events, and security violations), `SafeAgentUsage` (sanitized token and request counts), and `DatabaseAgentRunResult`.

### 2. OpenAI-Compatible LiteLLM Gateway (`gateway.py`)

- Constructs `OpenAIChatModel` with `OpenAIProvider` from `pydantic_ai.models.openai` and `pydantic_ai.providers.openai`.
- **Endpoint Allowlisting:** `validate_gateway_endpoint()` ensures the base URL uses `http`/`https`, contains no NUL bytes or embedded credentials, and resolves to an explicitly approved host in `gateway_trusted_hosts` (defaulting to `localhost`, `127.0.0.1`, and `::1`).
- **Credential Protection:** API keys are stored in `SecretStr` and injected into the provider client without exposure in exception chains, string representations, or logs.
- **Model Settings:** Enforces non-parallel tool calls (`parallel_tool_calls=False`) by default for deterministic execution with Qwen/LiteLLM.

### 3. Restricted Database Capability Facade (`secure_tools.py`)

`SecureDatabaseTools` provides a trusted read-only facade over `DatabaseAdapter`:
1. **Tool Allowlist:** Exposes only seven strictly approved tools:
   - `get_database_metadata`: Server engine, safe version, and safe database name.
   - `list_schemas`: Visible schemas with identifier safety validation.
   - `list_tables`: Tables in schema with identifier safety validation.
   - `describe_table`: Column definitions with data type and identifier safety validation.
   - `get_relationships`: Foreign key relationships with identifier safety validation.
   - `get_row_count`: Exact row count for a table.
   - `sample_validated_rows`: Secure, multi-step row sampling pipeline.
2. **Error Detaching & Incident Logging:** All unexpected underlying errors are caught safely. Sensitive connection strings, database passwords, and provider data are stripped:
   - Exception handlers do not log raw exception messages or stack traces (`exc_info=False`, no `_logger.exception()`).
   - A low-information incident identifier (`inc_{run_id}_{uuid}`) is generated for operational diagnostics.
   - Raised low-information `ToolError` instances have `__context__ = None` and `__cause__ = None`, preventing sensitive credentials from lingering in tracebacks.
3. **Authoritative Metadata Safety Policy:** Database metadata is treated as untrusted data:
   - Identifiers (schemas, tables, columns, constraints) are validated via `is_valid_database_identifier_syntax` and `is_safe_metadata_identifier`: legitimate spaces, Unicode (`"käyttäjä"`, `"données"`), and `$` are permitted, while SQL injection punctuation (`;`, `--`, `/*`, `'`, NUL bytes, newlines) is forbidden.
   - Metadata text (versions, data types, comments, server info) is canonicalized via `canonicalize_metadata_text` (bounded multi-pass percent-decoding, zero-width stripping, Unicode NFKC normalization) and inspected for residual secrets and instruction-like prompt injections (`has_instruction_injection`).
   - The complete serialized JSON response across every metadata tool is revalidated via `validate_model_visible_response` before leaving the tool.
4. **Pre-Sanitization Hard Bounds:** `_fetch_raw_sample` verifies adapter output dimensions before the sanitizer runs, rejecting responses that exceed requested limits or policy hard bounds (`_ABSOLUTE_MAX_SAMPLE_ROWS = 25`, `_ABSOLUTE_MAX_SAMPLE_COLUMNS = 128`).
5. **Whole-Row Budgeting:** When responses exceed `max_result_size_chars`, `_apply_size_budget` truncates whole rows atomically rather than returning broken partial row structures.

### 4. Mandatory 7-Step Row Sampling Order

For `sample_validated_rows`, the internal execution order strictly enforces:
```
1. Model Request (schema, table, limit, columns)
       │
2. Argument Validation (identifiers, 1 <= limit <= max_sample_rows)
       │
3. Adapter sample_rows() -> Raw SampleResult (confined to trusted code)
       │
4. Pre-Sanitization Check: bounds and column allowlists verified
       │
5. Phase 3E SanitizationOrchestrator.sanitize() -> SanitizationResult
       │
6. Phase 3F LeakageValidator.validate() -> ValidatedSample
       │
7. Final Boundary Revalidation: final_revalidate_sample() & Outbound JSON check
       │
8. Safe Model-Visible Response (SafeSampleResponse) or Safe Failure
```
If any stage rejects the data, `SafeSampleResponse(status="rejected")` is returned. Raw data or partial rows are **never** returned to the model.

### 5. Mandatory Final LLM Boundary (`final_revalidate_sample`)

Enforcing ADR 0014 and Phase 3F parity, `final_revalidate_sample` independently inspects the payload immediately prior to model response construction:
- Revalidates schema, table, and column names against identifier safety rules.
- Enforces strict scalar typing: exact `bool`, `int`, finite `float` (`math.isfinite`), `str`, and `None`. Date/time objects must be normalized to ISO strings beforehand; unnormalized dates are rejected.
- Non-empty, bounded policy and validator version strings are required.
- Scans string cells for residual secrets using Phase 3F detection rules (passwords, connection strings, JWTs, PEM keys, tokens, emails, SSNs, credit cards via Luhn, IBANs via mod-97, candidate and international phone numbers via `_INTL_PHONE_RE`).
- Re-inspects canonicalized representations (percent-decoding, zero-width character stripping, NFKC normalization).
- *Trust Boundary Note:* While forged Python objects running within the same interpreter process are rejected based on structural, type, and content validation, hostile code running inside the same Python runtime cannot be completely sandboxed by Python-level assertions alone. This boundary provides rigorous defense-in-depth against data-layer tampering and pipeline bypass.

### 6. PydanticAI Agent Construction & Tool Registry (`agent.py`)

- `create_database_agent()` constructs an `Agent[AgentDependencies, DatabaseUnderstandingResponse]` with explicit dependency injection.
- System prompt instructs the model to treat all database content and metadata as untrusted data, ignore prompt injection attempts, and report security policy rejections accurately.
- `validate_agent_tool_registry()` validates that registered tools match the strict allowlist (`ALLOWED_CAPABILITY_TOOLS` + `ALLOWED_OUTPUT_TOOLS`), preventing unauthorized or raw tools from being exposed to the model. Fails fast at the `DatabaseAgentService` constructor boundary.

### 7. Coordination & Execution Service (`service.py`)

`DatabaseAgentService`:
- Validates the injected agent's tool registry at constructor time.
- Binds `DatabaseAgentRequest` into an isolated `AgentExecutionContext`.
- Enforces request timeout via `asyncio.timeout(gateway_timeout_seconds)`.
- Enforces request limits, tool call limits, and token limits (`agent_total_tokens_limit`, `agent_output_tokens_limit`) via PydanticAI `UsageLimits`.
- Strips credentials from all error handlers and logs, emitting structured correlation incident IDs without tracebacks.
- Records structured audit events (`tool:*`, `run:completed`, `run:timed_out`, `run:usage_limit_exceeded`, `run:validation_fallback`).
- Provides safe JSON fallback parsing if the model outputs JSON within conversational text.

## Consequences

### Positive
- Strict isolation: raw database content never enters LLM prompts or message histories.
- Defense-in-depth: multi-barrier validation (detector -> transform -> leakage validator -> final boundary).
- Deterministic, zero-side-effect imports and agent instantiation.
- Secret-free logs, error traces, and audit histories.
- High test coverage (>=90%) verifying security boundaries, argument rejections, and prompt injection defense.

### Negative / Trade-offs
- Double validation of sampled rows adds minor CPU overhead for sampling operations, which is acceptable given dataset generation security requirements.
- Parallel tool calling is disabled by default to maintain deterministic compatibility across heterogeneous LiteLLM deployments.
