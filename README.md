# Automatic Dataset Generation Pipeline

Production-oriented internal infrastructure for generating ML and LLM datasets from enterprise
databases. The pipeline is being built in deliberately bounded phases; this repository currently
contains only the Phase 1 foundation.

## Current scope

Phase 1 establishes packaging, module boundaries, engineering standards, configuration, and tests.
It intentionally does **not** contain database implementations, MCP database tools, agent or
LiteLLM integration, dataset planning/generation/validation/publishing logic, CI, or containers.

The architecture uses a `src` layout and keeps domain/application behavior independent from
transport and infrastructure concerns. Future MCP handlers will translate requests and responses
only; business logic will remain in application modules. Database access will be exposed through
typed, read-only capabilities rather than arbitrary SQL.

See [ADR 0001](docs/adr/0001-system-architecture.md) for the decisions and current unknowns.

## Repository layout

```text
src/automatic_dataset_generation/
├── core/           # Runtime configuration and cross-cutting foundations
├── database/       # Future read-only database ports and adapters
├── mcp/            # Future MCP transport boundary
├── security/       # Future deterministic sanitization and policy enforcement
├── planning/       # Future dataset planning
├── generation/     # Future dataset generation
├── validation/     # Future dataset validation
├── publishing/     # Future registry abstraction and publishers
└── orchestration/  # Future use-case coordination
```

These concise names avoid repeating `dataset` inside a package already dedicated to dataset
generation. Each package is a boundary, not a commitment to speculative implementations.

## Development setup

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required. `pyproject.toml` defines dependency
intent; the committed `uv.lock` is the reproducible source for exact resolved versions. Create or
refresh the local environment from the lockfile, then install the Git hooks:

```bash
uv sync --extra dev --locked --python 3.12
uv run pre-commit install
```

Run the local quality checks:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pre-commit run --all-files
```

Pre-commit hook revisions are pinned independently because their execution environments are managed
by pre-commit. Ruff and mypy hook revisions track the versions resolved in `uv.lock`; update both
when intentionally upgrading either tool. Secret scanning uses pinned `detect-secrets` with a
committed baseline and verification disabled, so commits do not require an external SaaS service.
After reviewing any findings, maintain the baseline with:

```bash
uv run detect-secrets scan --all-files --baseline .secrets.baseline
uv run detect-secrets audit .secrets.baseline
```

## Configuration and secret handling

Runtime configuration uses environment variables with the `ADGP_` prefix. Copy `.env.example` to
`.env` for approved local configuration if desired. All `.env` files except `.env.example` are
ignored and must never be committed. Secrets must never be placed in source code.

Secret-bearing variables appear in `.env.example` only as empty contract entries. Provide real
values through the runtime environment, a CI/CD secret store, or an approved uncommitted `.env`
file. They use `SecretStr` and are hidden from normal settings representations, but arbitrary
serialization must not be treated as log-safe; diagnostic logging must use `safe_summary()`.
Secrets must never be written to prompts, logs, artifacts, tests, or source control.

Current variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADGP_ENVIRONMENT` | `development` | Runtime environment (`development`, `test`, `staging`, `production`) |
| `ADGP_LOG_LEVEL` | `INFO` | Application logging threshold |
| `ADGP_DATABASE_CONNECTION_STRING` | unset | Secret database connection string reserved for later phases |
| `ADGP_GATEWAY_API_KEY` | unset | Secret gateway credential reserved for later phases |

Generated datasets and run artifacts belong under the ignored `data/`, `artifacts/`, or `runs/`
directories. Files under `tests/fixtures/` may be committed when useful, but they must contain only
synthetic, non-sensitive test data.

## Development roadmap

- Phase 0 - architecture validation (completed externally)
- Phase 1 - foundation
- Phase 2 - database adapters + database MCP
- Phase 3 - security and sanitization
- Phase 4 - agent orchestration
- Phase 5 - dataset planner
- Phase 6 - dataset generator
- Phase 7 - validator
- Phase 8 - publisher
- Phase 9 - CI / Docker / production hardening

## Status

Phase 1 only. The unresolved registry endpoint and generation semantics documented in ADR 0001 must
be settled before their corresponding implementation phases.
