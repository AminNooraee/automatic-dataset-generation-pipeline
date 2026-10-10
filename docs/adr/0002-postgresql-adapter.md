# ADR 0002: PostgreSQL adapter

- Status: Accepted
- Date: 2026-10-10

## Decision

The first concrete adapter is PostgreSQL via psycopg 3. Each allowlisted adapter operation acquires
and closes an asynchronous connection; pooling is intentionally deferred. Before a query, the adapter
sets the session transaction characteristic to read-only and uses bound `set_config` to set a bounded
statement timeout. These controls are defense in depth and do not replace a least-privilege,
read-only PostgreSQL role.

Caller-supplied schema, table, and column names are composed with psycopg `Identifier` objects, while
ordinary values remain bound parameters. Sampling fetches no more than its requested limit plus one
row to report truncation. Driver exceptions are replaced with narrow, secret-safe domain errors.

## Consequences

There is no generic SQL API, no pooling, and no other engine implementation in this phase. PostgreSQL
metadata and relationship discovery remain constrained to visible, selectable relations.
