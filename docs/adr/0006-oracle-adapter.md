# ADR 0006: Oracle adapter

- Status: Accepted
- Date: 2026-10-12

## Decision

Phase 2G adds `OracleAdapter` as a distinct adapter for the `oracle` engine, using the official
python-oracledb 26.x driver in **Thin mode** (pure Python, no Oracle Client). The driver is added as
a top-level project dependency and to the mypy hook's `additional_dependencies`.

### Connection lifecycle

The adapter is native asyncio throughout: each allowlisted operation acquires one connection via
`oracledb.connect_async`, executes the single query, and releases it. There is no synchronous
`connect`, no `asyncio.to_thread`, and no connection pool. Connection components are passed as
decoded keyword arguments (`user`, `password`, `host`, `port`, `service_name`); credentials are never
interpolated into a raw string. Every URI component is validated in the constructor without
connecting: missing host/user/service name, a NUL byte in any credential field, any query or
fragment component, an out-of-range port, or an unsupported scheme/driver is rejected with a
generic, credential-safe message.

### Read-only enforcement and fail-closed setup

Each operation sets `autocommit = False` and then issues `SET TRANSACTION READ ONLY` as the **first**
statement before the application query. This is defense in depth, not an authorization boundary: a
least-privilege, read-only Oracle principal remains mandatory in production, and the transaction mode
is deliberately fail-closed — if the read-only transaction cannot be established, the operation raises
a domain error rather than proceeding.

### Timeouts

The per-round-trip statement timeout is the connection's `call_timeout`, which python-oracledb 26.x
Thin stores in a `uint32_t` **milliseconds**; it is set before the cursor is created and rounded up
with `ceil` so a positive sub-second value never truncates to zero. The login timeout is
`tcp_connect_timeout`, expressed in **seconds**. Both are validated as positive finite values;
`connect_timeout` is capped at `31_536_000` seconds and `call_timeout` at `4_294_967_295`
milliseconds so the millisecond value cannot overflow.

### Identifier safety and metadata

Caller-supplied schema, table, and column identifiers are composed with double-quoted delimiters and
embedded `"` doubled, using a private quoting helper that preserves case; empty identifiers and NUL
bytes are rejected. Ordinary filter values are named bind variables. Metadata is read from `ALL_*`
catalog views only (`all_users`, `all_tables`, `all_views`, `all_tab_columns`, `all_constraints`,
`all_cons_columns`) with no `DBA_*` requirement. `list_schemas` returns non-maintained users owning
visible tables or views; `list_tables` unions `all_tables` and `all_views` for one owner.

Column metadata joins `all_tab_columns` with an `all_constraints`/`all_cons_columns`
`constraint_type = 'P'` existence check for primary-key flags, so composite primary keys map to every
member column. Relationship discovery joins source and target constraints on `r_owner` and
`r_constraint_name`, pairs columns by matching `position` (composite FK mapping), matches the full
schema/table identity on either side, and includes cross-schema inbound relationships. Table
description maps ORA-00942/ORA-01031 to a not-found/not-visible error, gated on the exception being a
real `oracledb.DatabaseError` with a numeric Oracle code. Declared types render deterministically
(`NUMBER(p,s)`, `FLOAT(p)`, `CHAR`/`VARCHAR2`/`NCHAR`/`NVARCHAR2` with the CHAR/BYTE semantics,
`RAW(n)`), never inventing unsupported details.

`get_row_count` issues an exact `COUNT(*)` against the quoted table. Sampling uses
`FETCH FIRST (limit + 1) ROWS ONLY` to report truncation, with a configured hard maximum on the limit.

### Error boundary

Only driver and transport errors are converted to the narrow, credential-safe domain errors: the
boundary catches `oracledb.Error` (the base of all driver exceptions, including `DatabaseError` and
`InterfaceError`) plus raw transport-level `OSError` (such as a DNS `socket.gaierror`), and never
interpolates driver detail into the message. Unrelated programming errors propagate unchanged.
Cleanup (`rollback`, cursor close, connection close) is best-effort and suppresses only driver and
transport errors, so a close failure cannot replace an operation result or a prior safe error. The
adapter offers no generic SQL capability.

## Consequences

The system now covers all five enterprise engines named in ADR 0001. The remaining Phase 2 work is
the MCP database tools; MCP transport, sanitization, and all later phases are unchanged by this ADR.
