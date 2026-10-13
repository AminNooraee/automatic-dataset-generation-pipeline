# Automatic Dataset Generation Pipeline

Production-oriented internal infrastructure for generating ML and LLM datasets from enterprise
databases. The pipeline is being built in deliberately bounded phases; this repository currently
contains the Phase 1 foundation, Phase 2A/2B contracts, and Phase 2C/2D/2E/2F/2G/2H adapters.

## Current scope

Phase 1 establishes packaging, module boundaries, engineering standards, configuration, and tests.
Phase 2A adds typed relational engine and driver detection from connection-string URI schemes. It
does not establish database connections, and raw credentials remain protected by `SecretStr`.
Phase 2B adds typed engine-neutral metadata/result models, an asynchronous adapter contract, and a
dependency-injected adapter factory with no global registry. PostgreSQL, MySQL, MariaDB, Microsoft
SQL Server, Oracle, and SQLite adapters now implement that contract. MCP database tools, agent or
LiteLLM integration, dataset planning/generation/validation/publishing logic, CI, and containers
remain unimplemented.

The architecture uses a `src` layout and keeps domain/application behavior independent from
transport and infrastructure concerns. Future MCP handlers will translate requests and responses
only; business logic will remain in application modules. Database access will be exposed through
typed, read-only capabilities rather than arbitrary SQL.

See [ADR 0001](docs/adr/0001-system-architecture.md) for the decisions and current unknowns.

## Repository layout

```text
src/automatic_dataset_generation/
├── core/           # Runtime configuration and cross-cutting foundations
├── database/       # Connection parsing, metadata contracts, and adapter selection
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
- Phase 2A - connection parsing and engine detection (complete)
- Phase 2B - adapter contract and factory (complete)
- Phase 2C - PostgreSQLAdapter (complete)
- Phase 2D - MySQLAdapter (complete)
- Phase 2E - MariaDBAdapter (complete)
- Phase 2F - MSSQLAdapter (complete)
- Phase 2G - OracleAdapter (complete)
- Phase 2H - SQLiteAdapter (complete)
- Phase 2 (remainder) - MCP database tools (pending)
- Phase 3 - security and sanitization
- Phase 4 - agent orchestration
- Phase 5 - dataset planner
- Phase 6 - dataset generator
- Phase 7 - validator
- Phase 8 - publisher
- Phase 9 - CI / Docker / production hardening

## Status

Phase 2H. Connection parsing, adapter contracts, and adapter selection perform no network access.
PostgreSQL, MySQL, MariaDB, Microsoft SQL Server, Oracle, and SQLite adapters connect only when an
allowlisted operation runs. The unresolved registry endpoint and generation semantics documented in
ADR 0001 must be settled before their corresponding implementation phases.

## PostgreSQL adapter

Phase 2C provides `PostgreSQLAdapter` using psycopg 3. It creates one asynchronous connection per
allowlisted operation and configures each session as read-only with a bound statement timeout before
any catalog or application query. This is defense in depth: production roles must still be granted
least-privilege, read-only database permissions. Identifiers are composed with psycopg identifiers;
sampling is bounded by a configured hard maximum and never offers arbitrary SQL execution.

## MySQL adapter

Phase 2D provides `MySQLAdapter` using asyncmy. It opens one async connection per operation,
configures read-only transaction defaults and a bounded MySQL SELECT timeout, and exposes only
the typed adapter methods. Use a least-privilege, read-only MySQL account; session settings are
defense in depth. Sampling has a hard row limit. MariaDB is a separate Phase 2E adapter.
See [ADR 0003](docs/adr/0003-mysql-adapter.md).

## MariaDB adapter

Phase 2E provides `MariaDBAdapter` using the same asyncmy dependency. It opens one async
connection per operation, configures read-only transaction defaults, and bounds statements with
the MariaDB session variable `max_statement_time` expressed in (fractional) seconds rather than
MySQL's `max_execution_time` milliseconds. This is the principal reason MariaDB stays a distinct
adapter from MySQL. Use a least-privilege, read-only MariaDB account; session settings are defense
in depth. Sampling has a hard row limit. See [ADR 0004](docs/adr/0004-mariadb-adapter.md).

## Microsoft SQL Server adapter

Phase 2F provides `MSSQLAdapter` using mssql-python. It runs one synchronous connection per
operation on a dedicated worker thread (bridged to the event loop with `asyncio.to_thread`) and
exposes only the typed adapter methods. SQL Server has no PostgreSQL/MySQL-style session read-only
switch, so read-only access is enforced by a least-privilege principal plus allowlisted, SELECT-only
statements; `ApplicationIntent=ReadOnly` is a workload routing hint, not an authorization boundary.
Statement timeouts are set per connection in whole seconds before any cursor is created. Sampling
has a hard row limit. See [ADR 0005](docs/adr/0005-mssql-adapter.md).

## Oracle adapter

Phase 2G provides `OracleAdapter` using python-oracledb 26.x in Thin mode. It is native asyncio: one
`connect_async` connection per operation, with no worker thread and no pool. Each operation sets the
session to a read-only transaction as its first statement (fail-closed) and sets the driver's
`call_timeout` in milliseconds before any query. A least-privilege, read-only Oracle principal is
still mandatory; the transaction mode is defense in depth. Metadata comes from `ALL_*` catalog views
(no `DBA_*` requirement), identifiers use Oracle double-quoting, and relationships pair composite
primary/foreign key columns by position. `get_row_count` is an exact `COUNT(*)`; sampling is bounded
by `FETCH FIRST (limit + 1) ROWS ONLY`. Driver and transport errors are converted to credential-safe
domain errors; there is no generic SQL API. See [ADR 0006](docs/adr/0006-oracle-adapter.md).

## SQLite adapter

Phase 2H provides `SQLiteAdapter` using Python's standard-library `sqlite3`, with no added runtime
dependency. It supports only existing local file databases and opens one read-only connection per
operation in a worker thread. SQLite URI `mode=ro` is reinforced by verified `PRAGMA query_only`;
metadata uses `table_list`, `table_xinfo`, and `foreign_key_list`. Counts are exact and sampling is
bounded. The adapter exposes only `main`, does not support `:memory:`, `ATTACH`, network/UNC paths,
pooling, or generic SQL, and interprets `connect_timeout` as a lock-wait timeout. Statement timeouts
use SQLite's cooperative progress handler. See [ADR 0007](docs/adr/0007-sqlite-adapter.md).
