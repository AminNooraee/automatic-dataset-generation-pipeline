# ADR 0007: SQLite adapter

- Status: Accepted
- Date: 2026-10-13

## Decision

Phase 2H provides `SQLiteAdapter` using Python 3.12's standard-library `sqlite3`; no runtime
dependency is added. SQLite support is intended primarily for development and testing and accepts
only existing, local, file-backed databases. The URI contract is `sqlite:///relative/path.db` for a
process-relative path, `sqlite:////absolute/path.db` for an absolute POSIX path, and
`sqlite:///C:/path/database.db` for a Windows drive path; `sqlite+sqlite3` is equivalent. Authorities,
credentials, ports, user query strings and fragments, UNC/network paths, ambiguous endpoints, and
`:memory:` are rejected. In-memory databases are unsuitable because every adapter operation owns a
new connection.

The asynchronous contract is bridged with `asyncio.to_thread`. Each public operation performs its
entire synchronous lifecycle--connect, defensive configuration, progress-timeout setup, cursor use,
fetch, and cleanup--inside one worker invocation. Connections are never pooled or shared. Files are
opened through a safely percent-encoded SQLite file URI with `mode=ro`, and every connection then
executes and verifies `PRAGMA query_only = ON` before any catalog or application query. File URI
read-only mode is the primary file-level defense; `query_only` is defense in depth and is not treated
as equivalent to `sqlite3_db_readonly()`. The adapter exposes only allowlisted reads and no generic
SQL API.

`connect_timeout` maps to `sqlite3.connect(timeout=...)`, so for SQLite it is a database-lock wait
timeout rather than a network-connect timeout. `statement_timeout` installs a progress handler with
a monotonic deadline and a fixed 1,000-VM-instruction callback interval. It supports positive
fractional seconds but is a cooperative, approximate bound, not a hard real-time deadline. The
handler is removed during cleanup.

Only the logical `main` schema is exposed; `temp`, arbitrary attached schemas, and `ATTACH DATABASE`
are unsupported. Identifiers use double quotes with embedded quotes doubled. `PRAGMA main.table_list`
discovers ordinary tables, virtual tables, and views while excluding SQLite-maintained and shadow
objects. `PRAGMA main.table_xinfo` preserves declared types, column order, nullable metadata, and all
composite-primary-key members; hidden virtual-table implementation columns are excluded while
SELECT-visible generated columns remain. `PRAGMA main.foreign_key_list` discovers outbound and
inbound relationships by scanning eligible source tables and preserves composite pairs by foreign
key id and sequence; SQLite supplies no stable constraint name, so it remains `None`.

Row counts use exact `COUNT(*)`. Sampling safely quotes requested columns, binds `LIMIT ?` to one
more than the requested limit, fetches at most that amount, and returns raw standard SQLite values.
All `sqlite3.Error` failures become redacted domain operation errors; programming errors still
propagate, and no database path, raw URI, identifier, SQL text, or driver diagnostic appears in safe
errors or server metadata.

## Consequences

The Phase 2 database-adapter layer now covers PostgreSQL, MySQL, MariaDB, Microsoft SQL Server,
Oracle, and SQLite. SQLite metadata and read-only behavior are tested without network access by
creating only disposable temporary database files during test arrangement and opening them through
the adapter afterward. The next intended Phase 2 work is the safe Database MCP/tool layer; MCP and
Phase 3 behavior are not part of this decision.
