# Automatic Dataset Generation Pipeline

Production-oriented internal infrastructure for generating ML and LLM datasets from enterprise
databases. The pipeline is being built in deliberately bounded phases; this repository currently
contains the Phase 1 foundation, Phase 2A/2B contracts, Phase 2C/2D/2E/2F/2G/2H adapters, the
Phase 2I safe database MCP tool boundary, the Phase 3A sanitization contracts and policy, the
Phase 3B secret and credential detector, the Phase 3C PII detector, the Phase 3D
sanitization transforms, and the Phase 3E sanitization orchestrator.

## Current scope

Phase 1 establishes packaging, module boundaries, engineering standards, configuration, and tests.
Phase 2A adds typed relational engine and driver detection from connection-string URI schemes. It
does not establish database connections, and raw credentials remain protected by `SecretStr`.
Phase 2B adds typed engine-neutral metadata/result models, an asynchronous adapter contract, and a
dependency-injected adapter factory with no global registry. PostgreSQL, MySQL, MariaDB, Microsoft
SQL Server, Oracle, and SQLite adapters now implement that contract. Phase 2I exposes those
adapters through a safe FastMCP database tool boundary. Phase 3A adds the deterministic security
contracts and the fail-closed `SanitizationPolicy`: immutable, metadata-only field and
classification contracts, an LLM-eligible `SanitizedSample` boundary, and a classification-to-action
policy. Phase 3A defines these contracts and the policy only; it performs no detection,
transformation, or leakage validation. Phase 3B adds the deterministic `SecretCredentialDetector`:
a no-LLM classifier that scans raw `SampleResult` rows for secrets and credentials and returns
safe, metadata-only field classifications (`credential`, `secret`, or `unknown`) bounded by
per-cell and sample-wide limits. It emits no raw or matched values and performs no transformation.
Phase 3C adds the deterministic `PIIDetector`, a second no-LLM classifier over the same raw
`SampleResult` that returns safe, metadata-only field classifications of `pii` or `unknown`. It
uses conservative tokenized column/nested-key name matching plus a small set of high-confidence,
whole-value patterns (email, international phone, IP, MAC, Luhn-validated card numbers, and
MOD-97-validated IBANs); there is no entropy-only detection and no free-text value scanning. It
emits no raw or matched values and performs no transformation. Phase 3D adds the deterministic
`SanitizationTransformer`, which applies one already-resolved `SanitizationAction` to one raw
value: `allow` checks and normalizes the scalar domain, `redact`/`mask` return a fixed marker that
reveals no length or type, `drop` is distinguishable from a genuine `None`, and `pseudonymize`
returns a keyed, collision-safe, length- and type-independent token derived from HMAC-SHA256 over a
canonical byte encoding (the HMAC key is supplied by the operator as a `SecretStr`, never
hardcoded). Phase 3E adds the deterministic `SanitizationOrchestrator`, which runs both detectors
over a raw `SampleResult`, merges classifications using a policy-aware precedence rule, resolves
actions through `SanitizationPolicy`, applies cell transformations, handles dropped columns, and
produces an immutable `SanitizationResult` containing a `SanitizedSample` and `SanitizationReport`.
Phase 3E performs sanitization only; validating that a sample is leakage-free is deferred to
mandatory Phase 3F. Agent or LiteLLM integration, dataset
planning/generation/validation/publishing logic, CI, and containers remain unimplemented.

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
├── mcp/            # Safe FastMCP database tool boundary (Phase 2I)
├── security/       # Sanitization contracts/policy (3A), secret/credential (3B), PII (3C), transforms (3D), orchestrator (3E); 3F deferred
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
- Phase 2I - safe database MCP tool boundary (complete)
- Phase 3A - sanitization contracts and policy (complete)
- Phase 3B - secret / credential detection (complete)
- Phase 3C - PII classification (complete)
- Phase 3D - sanitization transforms (complete)
- Phase 3E - sanitization orchestration (complete)
- Phase 3F - leakage validation
- Phase 4 - agent orchestration
- Phase 5 - dataset planner
- Phase 6 - dataset generator
- Phase 7 - validator
- Phase 8 - publisher
- Phase 9 - CI / Docker / production hardening

## Status

Phase 3E. Connection parsing, adapter contracts, and adapter selection perform no network access.
PostgreSQL, MySQL, MariaDB, Microsoft SQL Server, Oracle, and SQLite adapters connect only when an
allowlisted operation runs. Phase 2I wraps those adapters in a safe FastMCP database tool boundary
that exposes exactly seven read-only tools, takes no connection strings or credentials as tool
arguments, never accepts arbitrary SQL, and returns raw (unsanitized) sample rows that must pass
through Phase 3 before reaching an LLM.

Phase 3A adds the security and sanitization contracts and the fail-closed `SanitizationPolicy` only:
immutable, metadata-only field and classification contracts, the LLM-eligible `SanitizedSample`
boundary, and a classification-to-action policy. It performs no detection, transformation, or
leakage validation. Constructing a `SanitizedSample` does not prove the data is leakage-free; that
remains a later, separate step (Phase 3F) before any LLM exposure. The unresolved registry endpoint
and generation semantics documented in ADR 0001 must be settled before their corresponding
implementation phases.

Phase 3C adds the deterministic `PIIDetector`, a second no-LLM, no-entropy classifier over the same
raw `SampleResult` that returns metadata-only `pii`/`unknown` field classifications. It uses
conservative tokenized column and nested-key name matching plus a small set of high-confidence,
whole-value patterns (email, international phone with an explicit `+` country code, IPv4/IPv6 via
Python's `ipaddress`, canonical MAC, standalone Luhn-valid payment cards, and IBANs only when
MOD-97-valid). It performs no free-text value scanning for names, addresses, dates of
birth, or national IDs, and like Phase 3B it emits no raw or matched value, fails closed on
oversized or uninspectable input, and performs no transformation. See
[ADR 0011](docs/adr/0011-pii-detection.md).

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

## Database MCP

Phase 2I provides a safe database MCP tool boundary built on FastMCP 4.x. A trusted, already-built
`DatabaseAdapter` is injected; the boundary takes no connection string or credential as a tool
argument and never accepts arbitrary SQL. It exposes exactly seven read-only tools: `get_server_info`,
`list_schemas`, `list_tables`, `describe_table`, `get_relationships`, `get_row_count`, and
`sample_rows`. MCP-level policy limits bound the requested row `limit`, explicit column count,
nested depth, and total encoded values. Adapter errors are translated to fixed, low-information
tool errors. `sample_rows` returns raw, **unsanitized** rows that must pass through the Phase 3
security and sanitization layer before they may reach an LLM. `create_database_mcp` returns a server
without starting a network transport, and importing the module performs no database or network
activity. See [ADR 0008](docs/adr/0008-database-mcp.md).

## Sanitization

Phase 3A provides the security and sanitization contracts and the fail-closed `SanitizationPolicy`
only. `SampleResult` remains trusted raw, **unsanitized** data and never reaches a prompt. The
metadata-only contracts `FieldReference`, `FieldClassification`, and `SanitizationDecision` carry no
raw or matched cell value. `SanitizedSample` is the distinct, LLM-eligible boundary contract; it
accepts only the `SanitizedValue` domain (`None`, `bool`, `int`, finite `float`, `str`), rejects
arbitrary driver or database objects and non-finite floats, and hides its rows from `repr`. Its rows
may not contain raw, unsanitized data. Constructing a `SanitizedSample` does not by itself prove the
data is leakage-free; leakage validation is a later, separate step (Phase 3F).

`SanitizationPolicy` is immutable and fail-closed. It maps every `SensitivityClass` to a
`SanitizationAction`; `pii`, `secret`, `credential`, and `unknown` can never map to `allow`, and the
default policy is `non_sensitive -> allow`, `pii -> pseudonymize`, and `secret`, `credential`, and
`unknown` -> `redact`. The mapping is stored as an immutable `Mapping` snapshot, so external mutation
cannot change policy behavior. `SanitizationReport` carries counts and policy lineage only. Phase 3A
performs no detection, transformation, or pseudonymization. See
[ADR 0009](docs/adr/0009-sanitization-contracts-policy.md).

Phase 3B adds the deterministic `SecretCredentialDetector`. Given a raw `SampleResult`, it performs
no-LLM, bounded scanning and returns a metadata-only `SecretDetectionResult` classifying fields as
`credential`, `secret`, or `unknown`. It uses conservative tokenized column and nested-key matching
plus a small set of high-confidence value patterns (PEM private keys, `Bearer`/`Basic` headers, JWT
structure, URI user-info passwords, and key/value assignments); there is no entropy-only detection.
It emits **no** raw or matched value, never stringifies arbitrary uninspectable objects (such values
are classified `unknown`), and fails closed on oversized or uninspectable input. Scanning is bounded
per cell (depth and element limits), by a sample-wide `max_cells`, and by a shared sample-wide
`max_total_container_elements`; overflow aborts the scan with a low-information `SecretDetectionError`
and no partial result. Phase 3B classifies only; it performs no redaction, masking, or
pseudonymization and constructs no `SanitizedSample`. See
[ADR 0010](docs/adr/0010-secret-credential-detection.md).

Phase 3C adds the deterministic `PIIDetector`, a second no-LLM, no-entropy detector over the same raw
`SampleResult` that returns a metadata-only `PIIDetectionResult` classifying fields as `pii` or
`unknown`. It uses conservative tokenized column and nested-key matching plus a small set of
high-confidence, whole-value patterns (email, international phone with an explicit `+` country code,
IPv4/IPv6 via Python's `ipaddress`, canonical MAC, standalone Luhn-valid payment cards, and IBANs
only when MOD-97-valid). It performs no free-text value scanning for person names,
postal addresses, dates of birth, or national IDs, and there is no entropy-only detection. It emits
**no** raw or matched value, fails closed on oversized or uninspectable input, and mirrors Phase 3B's
bounded scanning (`max_cells` plus the shared sample-wide `max_total_container_elements`, with
overflow aborting via a low-information `PIIDetectionError`). Phase 3C classifies only; it performs
no redaction, masking, or pseudonymization and constructs no `SanitizedSample`. See
[ADR 0011](docs/adr/0011-pii-detection.md).

Phase 3D adds the deterministic `SanitizationTransformer`, which applies one already-resolved
`SanitizationAction` to one raw value and returns a metadata-aware `SanitizationTransformResult`.
`allow` checks the `SanitizedValue` domain and normalizes safe types (`Decimal`, `date`/`datetime`/
`time`, `UUID`, and bounded UTF-8-decodable bytes) or rejects fail-closed; `redact` and `mask` return
a fixed marker (`[REDACTED]` / `[MASKED]`) that reveals no length or type; `drop` sets `dropped` and
carries no value, so it is distinguishable from a genuine `None`; and `pseudonymize` returns a keyed,
collision-safe token from HMAC-SHA256 over a type-explicit canonical byte encoding. The HMAC key is
supplied by the operator as a `SecretStr` (32-4096 bytes, never hardcoded, never disclosed), and there
is no stored mapping, so pseudonyms are non-reversible without it. Every value is bounded by its own
`SanitizationTransformConfig`, no generic `str()`/`repr()` is called on arbitrary objects, and the
error/result never echo a raw value. Phase 3D transforms one value only; it does not run the
detectors, merge findings, build a `SanitizedSample`, or validate leakage (Phase 3E and 3F). See
[ADR 0012](docs/adr/0012-sanitization-transforms.md).

Phase 3E adds the deterministic `SanitizationOrchestrator`, which coordinates the complete sanitization
pipeline over a raw `SampleResult`. It validates actual sample dimensions against bounded resource
limits (`max_fields`, `max_rows`, `max_cells`), runs both `SecretCredentialDetector` and `PIIDetector`,
merges their findings using a documented, policy-aware precedence rule (`DROP > REDACT / MASK > PSEUDONYMIZE > ALLOW`
with sensitivity severity tie-breaking) that never weakens protection, classifies unclassified fields as
`unknown` (fail-closed), maps sensitivities to actions via `SanitizationPolicy`, applies
`SanitizationTransformer` per cell, filters dropped columns without confusing them with legitimate nulls,
enforces mandatory pseudonymization keys, and returns an immutable `SanitizationResult` containing a
`SanitizedSample` and `SanitizationReport`. Failure is atomic: any processing error aborts the run
with public exceptions cleanly detached from internal exception chains (`__context__` and `__cause__`
stripped) to prevent leaking injected or matched sensitive material. Detected sensitive values are never
exposed raw without policy protection, while explicitly approved non-sensitive values may remain in
normalized form; payload serialization (`model_dump()`) carries row values and is NOT log-safe.
Constructing a `SanitizedSample` does not by itself prove the sample is leakage-free; that remains the
mandatory responsibility of Phase 3F before any LLM exposure. See
[ADR 0013](docs/adr/0013-sanitization-orchestrator.md).
