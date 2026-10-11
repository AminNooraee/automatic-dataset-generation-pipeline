# ADR 0004: MariaDB adapter

- Status: Accepted
- Date: 2026-10-11

## Decision

Phase 2E adds `MariaDBAdapter` as a distinct adapter for the distinct `mariadb` engine, using the
same already-pinned asyncmy 0.2.x dependency as the MySQL adapter. asyncmy speaks the wire protocol
used by both servers, so no new driver or dependency is introduced.

MariaDB remains a separate adapter rather than being folded into `MySQLAdapter` because its
session-level control for bounding long-running statements is different. MariaDB does not offer the
MySQL `max_execution_time` variable; it uses `max_statement_time`, which is measured in **seconds**
and accepts fractional values. Mixing the two would force a shared timeout representation that is
wrong for one of the engines, so the adapters are kept separate and do not share a timeout path.

### Connection lifecycle

Each allowlisted operation opens one asyncmy connection with `autocommit=True` and releases it when
the operation finishes; there is no pool. Shutdown is best-effort and ordered: the adapter first
awaits `connection.ensure_closed()` to send the protocol termination gracefully, then calls
`connection.close()` as a cleanup safeguard that releases the local transport. A failure in either
step is suppressed (only driver and transport errors) so it cannot replace an operation's result or
a prior safe error, and no stronger release guarantee is claimed.

### Read-only defense in depth

Before any metadata or application query, the session sets `SET SESSION TRANSACTION READ ONLY`.
MariaDB documents this as setting the default access mode for subsequent transactions in the
session. With `autocommit=True` each statement runs in its own auto-committed transaction that
therefore inherits read-only mode. If this statement fails, the adapter fails closed: no subsequent
query runs because the failure surfaces before the application query executes. The session setting
is defense in depth only; production credentials must still be least-privilege and read-only. The
server-global `read_only` variable is deliberately never modified.

### Statement timeout

Before any metadata or application query, the session sets
`SET SESSION max_statement_time = <seconds>`. The value is the configured `statement_timeout`
expressed in **seconds**, and fractional seconds are preserved: `10` → `10`, `0.5` → `0.5`,
`0.0004` → `0.0004`. Values are never converted to MySQL milliseconds. The accepted range is
`0 < statement_timeout <= 31_536_000` seconds, matching MariaDB's documented bound. If this
statement fails, the adapter fails closed.

Because the `SET ... max_statement_time` grammar does not guarantee a parameter marker, the literal
is composed as a plain fixed-point decimal derived from the validated numeric value via a `Decimal`.
The input is strictly validated (positive, finite, in-range, never bool) before the literal is
built, so no caller-controlled text, NaN, or Infinity can reach SQL, and no floating-point artifact
or scientific notation appears in the generated statement.

### Identifier safety and metadata

Caller-supplied schema, table, and column identifiers are quoted with backticks and embedded backticks
doubled, using a private quoting helper. Empty identifiers and NUL bytes are rejected. Ordinary
values are bound parameters. Metadata is read from `INFORMATION_SCHEMA`: `SCHEMATA` for visible
schemas, `TABLES` for visible base tables, system-versioned tables, and views, `COLUMNS` with a
schema/table-scoped
`STATISTICS` `INDEX_NAME = 'PRIMARY'` existence check for column metadata and composite primary
keys, and `KEY_COLUMN_USAGE` for direct foreign-key column pairs. Table-scoped relationship
discovery matches the complete schema/table identity on either side. Sampling uses SQL `LIMIT` with
one extra row and a configured hard maximum.

### Error boundary and scope

Only asyncmy driver errors are converted into the generic, credential-safe domain errors; unrelated
Python errors propagate unchanged. `describe_table` maps missing or inaccessible objects to
`DatabaseObjectNotFoundError`. The adapter offers no generic SQL capability.

## Consequences

The system now covers three of the four enterprise engines named in ADR 0001. Remaining Phase 2 work
is the MariaDB-adjacent engines (Microsoft SQL Server and Oracle) and the MCP database tools; MCP
transport, sanitization, and all later phases are unchanged by this ADR.
