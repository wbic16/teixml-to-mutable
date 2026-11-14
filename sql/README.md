# Vendored Mutable OS knowledge-schema migrations

The SQL files under `migrations/` are **byte-identical copies** of the
knowledge-schema migrations from **wbic16/mutable-os** (MIT — declared in
that repo's `package.json`; no separate LICENSE file at its root), taken
from `src/knowledge-sqlite/migrations/` at main commit
`acb8130` (2026-11-14):

- `mutable/0001-foundation.sql` … `mutable/0010-cardex-soft-delete.sql`
  (schema version 10)
- `audit/0001-foundation.sql` (schema version 1)

They are vendored, not re-typed, on purpose: Mutable validates a database
by comparing the SHA-256 of each migration file and a structure hash of
`sqlite_schema` against its own copies. Applying the same bytes is what
makes the databases this crate produces the real schema — the per-file
SHA-256 values recorded in each database's `SchemaInfo` table are these
files' hashes (e.g. mutable 0001 =
`fc74d6f07b6f655976e20ed08c9e5a01877d5a3787716124d0822213e0d0fb77`).

If Mutable's schema advances, re-vendor the new files, update the
migration list in `src/mutable.rs`, and re-run the acceptance suite
against Mutable's own code before shipping.
