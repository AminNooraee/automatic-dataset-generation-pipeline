# ADR 0005: Microsoft SQL Server adapter

- Status: Accepted
- Date: 2026-10-12

## Decision

Phase 2F adds `MSSQLAdapter` as a distinct adapter for the `mssql`/`sqlserver` engine, using the
new mssql-python 1.x driver. The driver is a native ODBC provider, so it is added as a top-level
project dependency and to the mypy hook's `additional_dependencies`.

### Connection lifecycle and thread boundary

mssql-python is a synchronous, ODBC-backed driver with no async API. Each allowlisted operation
therefore opens one connection, sets its per-statement timeout, executes the single query, fetches
the rows, and releases both cursor and connection — all inside one synchronous method
(`_run_query_sync`) run on a worker thread via `asyncio.to_thread`. Only plain rows and column
metadata cross back to the event loop; the synchronous `Connection` object is never held on, used,
or observed by the event loop after the operation completes. There is no pool. Cursor and
connection shutdown are best-effort and suppress only driver and transport errors so a close
failure cannot replace an operation's result or a prior safe error.

### Read-only enforcement

SQL Server offers no PostgreSQL/MySQL-style session read-only switch. Read-only behavior is
therefore enforced two ways: the adapter issues only allowlisted, SELECT-only statements, and
production must grant a least-privilege principal. `ApplicationIntent=ReadOnly` is passed as a
workload routing hint to a read-only replica; it is an ODBC connection hint, not an authorization
boundary, and the adapter never relies on it to prevent writes.

### Statement timeout

Because the whole synchronous lifecycle runs in a worker thread, there is no async `statement`
handle to cancel. The driver's per-connection query timeout (`connection.timeout`, in whole
seconds) is set before any cursor is created, since cursors snapshot the value at creation. The
configured `statement_timeout` is rounded up with `ceil` to a positive whole number of seconds so a
positive sub-second value never truncates to zero, and is capped at the adapter policy maximum
`31_536_000` seconds. The login timeout shares the same validation and cap. The accepted range for
both is `0 < timeout <= 31_536_000`.

### Connection string and endpoint safety

The connection components are parsed from the URI with `urlsplit`. Dynamic values (`server`,
`uid`, `pwd`, `database`) and the fixed security configuration are all passed as keyword arguments
to `mssql_python.connect`; credentials are never interpolated into a raw string by the adapter. The
`server` endpoint is composed as `host,port` for normal hosts and bracketed `[ipv6]:port` for
IPv6 literals. Host values that could alter ODBC endpoint syntax — `;`, `,`, `\`, NUL, any
whitespace, or leading/trailing padding — are rejected, as are NUL bytes in the database name,
any query or fragment component, out-of-range ports, and missing host/user/database.

### Identifier safety and metadata

Caller-supplied schema, table, and column identifiers are quoted with bracket delimiters and
embedded `]` doubled, using a private quoting helper. Empty identifiers and NUL bytes are rejected.
Ordinary filter values are bound parameters. Metadata is read from `sys.*` catalog views: `sys.schemas`
joined to `sys.objects` for visible schemas and tables (types `U` base tables and `V` views,
`is_ms_shipped = 0`), `sys.columns` joined to `sys.types` (via `system_type_id`) with a
`sys.indexes`/`sys.index_columns` `is_primary_key` existence check for column metadata and composite
primary keys, and `sys.foreign_keys`/`sys.foreign_key_columns` for direct foreign-key column pairs.
`HAS_PERMS_BY_NAME` filters objects the configured principal can SELECT. Table-scoped relationship
discovery matches the complete schema/table identity on either side. Declared types are rendered
deterministically from `sys.columns`/`sys.types` values (`nchar`/`nvarchar` halve `max_length`;
`-1` renders `max`). Sampling uses SQL `TOP` with one extra row and a configured hard maximum.

### Error boundary and scope

Only mssql-python driver errors are converted into the generic, credential-safe domain errors;
unrelated Python errors propagate unchanged. `describe_table` maps an empty result set to
`DatabaseObjectNotFoundError`. The adapter offers no generic SQL capability.

## Consequences

The system now covers four of the enterprise engines named in ADR 0001. Remaining Phase 2 work is
the Oracle adapter and the MCP database tools; MCP transport, sanitization, and all later phases
are unchanged by this ADR.
