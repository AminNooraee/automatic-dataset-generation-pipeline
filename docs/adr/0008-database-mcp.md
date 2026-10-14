# ADR 0008: Safe database MCP tool boundary

- Status: Accepted
- Date: 2026-10-13
- Scope: Phase 2I - Safe Database MCP core

## Context

Phases 2C through 2H delivered engine-neutral, read-only database adapters behind a single
asynchronous contract. The pipeline still needs a way to expose those capabilities to an agent
without letting the agent reach a connection string, a credential, or arbitrary SQL. MCP is the
chosen tool-integration protocol and FastMCP provides the implementation (ADR 0001, decision 3).

This ADR records how Phase 2I turns the existing adapters into a safe MCP tool boundary. It is a
transport and safety boundary, not an application layer: it translates requests and responses only
and delegates all database behavior to an injected adapter.

## Decision

1. **Implementation.** The boundary is built on FastMCP 4.x. `create_database_mcp` constructs a
   `FastMCP` server (with `mask_error_details` and `strict_input_validation` enabled) and returns
   it without starting a network transport. Importing the module performs no database, network, or
   transport activity.

2. **Adapter injection.** A `DatabaseAdapter` instance is supplied by trusted code to
   `DatabaseToolService` and `create_database_mcp`. The service never builds a connection and never
   reads `adapter._connection_spec`. The raw `DatabaseConnectionSpec` is never a tool argument and
   is never part of any tool input or output schema.

3. **Exact allowlist.** The server exposes exactly seven tools and no generic SQL-equivalent tool:
   `get_server_info`, `list_schemas`, `list_tables`, `describe_table`, `get_relationships`,
   `get_row_count`, and `sample_rows`. Each tool maps one-to-one onto the corresponding adapter
   method. No tool accepts `execute`, `query`, or free-form SQL.

4. **No credentials in tool input.** Tool inputs are restricted to identifier strings
   (`schema`, `table`, `column`) and bounded `sample_rows` parameters (`limit`, `columns`). There is
   no `connection_string`, `password`, `api_key`, or equivalent parameter on any tool.

5. **MCP-level policy.** `DatabaseToolPolicy` defines MCP-level limits that are independent of an
   adapter's own hard limits and are validated at construction:
   - `max_sample_rows` (default 25) caps the requested row `limit`; `bool` is rejected.
   - `max_sample_columns` (default 128) caps an explicit `columns` list.
   - `max_container_depth` (default 8) caps nested container depth during encoding.
   - `max_encoded_values` (default 10,000) caps total encoded scalar/container elements.
   These are MCP-level guards; adapters still enforce their own authoritative hard limits.

6. **Structural input validation.** Before any adapter call, identifiers must be non-empty strings
   containing no NUL byte. `sample_rows` requires `1 <= limit <= max_sample_rows` (bool rejected),
   accepts `columns` of `None` (adapter default) or a non-empty list bounded by `max_sample_columns`,
   preserves column order, and converts the list to a tuple before calling the adapter. Invalid
   input raises before the adapter is invoked.

7. **Safe error translation.** `DatabaseObjectNotFoundError` and `DatabaseAdapterError` are
   translated to fixed, low-information `ToolError` messages ("Database object is unavailable" and
   "Database tool operation failed"). Adapter exception text, connection details, identifiers, SQL,
   and driver diagnostics never reach the tool caller, including synthetic secret markers.

8. **Raw, unsanitized sample data.** `sample_rows` returns *trusted raw* rows. They are **not**
   sanitized. The response type documents that this data must pass through the future security and
   sanitization layer (Phase 3) before it may be exposed to an LLM.

9. **Explicit JSON-safe transport encoding.** A dedicated encoder maps a fixed set of database
   value types to JSON-safe representations: `None`, `bool`, `int`, finite `float`, `str`,
   `bytes`/`bytearray`/`memoryview` (base64), `Decimal`, `datetime`, `date`, `time`, `UUID`, nested
   `list`/`tuple`, and `Mapping` with string keys. Non-finite floats are encoded as labeled
   structures rather than invalid JSON. Unknown object types fail safely (`ToolError`) - the
   encoder never falls back to `str(value)` or `repr(value)`. Depth and element-count bounds are
   enforced during encoding, and the source `SampleResult` is not mutated.

10. **Size/depth/element guards.** The policy bounds from decision 5 are enforced both on request
    (limit and column count) and on result (row count, column count, and per-value depth and
    element count during encoding). An oversized or unencodable result produces a `ToolError`
    rather than truncated or invalid output.

11. **In-process testing.** Tests use a fake `DatabaseAdapter` and FastMCP's in-memory
    `Client`/server. No real database, network, or MCP transport is used; construction and tool
    calls are proven in-process, including one safe `ToolError` path.

## Consequences

- The agent receives constrained, typed database capabilities and never a connection string,
  credential, or arbitrary-SQL tool, satisfying ADR 0001 decisions 4 and 5.
- The boundary is thin and testable without live infrastructure; it can be swapped for a real
  transport later without touching database behavior.
- Sample rows cross the MCP boundary as raw data, so a distinct sanitization phase is a hard
  prerequisite before any sampled value reaches a prompt.

## Next phase

Phase 3 - Security and sanitization. A deterministic security and sanitization layer must process
`sample_rows` output (and any database-derived content) before it may reach an LLM.
