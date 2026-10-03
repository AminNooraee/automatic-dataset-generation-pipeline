# ADR 0001: System architecture

- Status: Accepted
- Date: 2026-10-03
- Scope: Architecture validated before Phase 1

## Context

The system will generate ML and LLM datasets from enterprise databases. It must operate safely in
an internal production environment where source data and credentials are sensitive. The codebase
also needs durable boundaries so database access, agent behavior, transports, validation, and
publishing can evolve independently and be tested without live infrastructure.

Phase 0 experiments validated the principal technology and security direction. Phase 1 records
those decisions and establishes the repository foundation; it does not implement later-phase
capabilities.

## Decision

1. The runtime and development baseline is Python 3.12 with strong static typing.
2. PydanticAI will provide the agent layer. Qwen will be accessed through an OpenAI-compatible
   LiteLLM gateway. Dify may be integrated later but is optional and is not a core dependency.
3. MCP is the tool-integration protocol and FastMCP will provide its implementation. MCP handlers
   will be thin transport adapters; they will not contain business logic.
4. Enterprise data access will use custom, read-only database adapters. The engine will be selected
   from the connection-string scheme. The agent will receive constrained capabilities and will
   never be given an arbitrary-SQL tool.
5. Deterministic security checks and sanitization will run before any database-derived content can
   reach an LLM. Connection strings, passwords, API tokens, and other secrets must never reach
   prompts, logs, generated artifacts, or source control.
6. Dataset publishing will depend on a registry abstraction. An HF-compatible implementation may
   satisfy that contract once the internal endpoint is available.
7. Integration with the existing fine-tuning pipeline will occur through explicit dataset and
   manifest contracts rather than shared implementation details.
8. Modules are separated by responsibility: core configuration, database infrastructure, MCP
   transport, security, planning, generation, validation, publishing, and orchestration. Dependencies
   should point toward stable contracts and domain behavior, not infrastructure details.
9. Runtime configuration comes from environment variables. Secret values use secret-aware types and
   are excluded from safe diagnostic views. No global mutable configuration singleton is provided.
10. Concrete database adapters will implement one asynchronous, engine-neutral contract. Adapter
    selection uses constructor-injected builders copied into each factory instance; there is no
    global mutable adapter registry or automatic plugin discovery.

## Consequences

- Infrastructure can be substituted in tests and later deployments without coupling domain logic to
  a specific database, transport, model gateway, or registry.
- Read-only, capability-based database access and deterministic sanitization create multiple explicit
  security boundaries.
- More wiring will be required than in a single-module application, but ownership and testing
  boundaries remain clear.
- Later phases must define contracts before implementing integrations. This ADR does not authorize
  placeholder adapters or speculative workflow code in Phase 1.

## Unresolved items

- Real PostgreSQL, MySQL, Microsoft SQL Server, and Oracle adapters are not implemented yet.
- The internal HF-compatible dataset registry endpoint is not yet available.
- The exact semantics of "10 outputs per record" are not yet confirmed, including whether the count
  is a target, a maximum, or a requirement and how rejected outputs affect it.

These items remain intentionally open and must be resolved in their relevant future phases.

## Out of scope for Phase 1

Database adapters, arbitrary SQL, production MCP database tools, the dataset planner, generator,
validator and publisher, an HF registry client, agent orchestration, LiteLLM integration code,
CI/CD, and Docker are not implemented in this phase.
