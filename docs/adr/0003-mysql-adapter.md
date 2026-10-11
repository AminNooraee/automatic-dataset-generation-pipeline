# ADR 0003: MySQL adapter

- Status: Accepted
- Date: 2026-10-11

## Decision

Phase 2D uses asyncmy 0.2.x for native asyncio MySQL access. Each allowlisted operation
opens one asyncmy connection and performs graceful shutdown when the operation finishes; no pool is
used. Before releasing the connection, the adapter awaits `connection.ensure_closed()` to send the
protocol termination gracefully and then calls `connection.close()` as a cleanup safeguard that
releases the local transport. This ordering best-effort shuts the connection down; a failure in
either step is suppressed so it cannot replace the operation's result or a prior safe error, and no
stronger release guarantee is claimed. The connection uses
autocommit and first sets `SET SESSION TRANSACTION READ ONLY` so subsequent statements
inherit a read-only transaction mode. This is defense in depth; the configured database
account must still have least-privilege, read-only grants. MySQL read-only transactions
do not prevent changes to session-local temporary tables.

Each connection also sets session `max_execution_time` before metadata or application
queries. MySQL measures this in integer milliseconds and applies it to read-only SELECT
statements, with documented limitations for stored programs. Fractional milliseconds
round up, and the adapter rejects values above MySQL's supported maximum. The SET
statement uses only an internally validated integer literal because parameter markers
are not guaranteed for this SQL grammar.

The private URI parser handles standard URL authority fields and percent decoding;
credentials remain under `SecretStr`. Caller identifiers are enclosed in backticks
and embedded backticks are doubled. Values use driver parameters. Metadata comes from
`INFORMATION_SCHEMA`: SCHEMATA and TABLES for visible objects, COLUMNS with a
schema/table-scoped STATISTICS PRIMARY-index existence check for columns and composite
primary keys, and KEY_COLUMN_USAGE for direct composite foreign-key column pairs.
Table-scoped relationship discovery matches the complete schema/table identity on
either side. Sampling uses SQL LIMIT with one extra row and a configured hard maximum.

Only asyncmy driver errors cross into generic, credential-safe operation errors;
unrelated Python errors propagate. The adapter offers no generic SQL capability.
MariaDB remains a separate engine and will have its own Phase 2E adapter.
