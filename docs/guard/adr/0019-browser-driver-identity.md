# ADR 0019: Browser driver identity and the per-driver schema ledger

Status: accepted.

## Context

A site grant (see the [browser protection design](../browser-protection-prd.md), section 5.5) covers the routine
actions of one browser driver on one site, whichever of the driver's profiled tools performs them. The grant has to
end whenever the driver it was given to is no longer the same driver: another profile, another server, or a tool
whose schema changed since the grant was given.

The first draft defined the driver identity hash as one digest over the server identity and the `tool_identity_hash`
and `schema_hash` of every tool the profile maps. A hook sees one tool call at a time and never the full tool list,
so it cannot compute that digest. Some calls also arrive with no schema hash at all.

## Decision

The driver identity has two parts.

- **Driver key**: a digest over the driver profile id, the profile digest, the MCP server name and the server's
  `server_identity_hash`. It names the driver and keys its ledger.
- **Schema ledger**: one row per driver key with a schema epoch, and one row per profiled tool seen with its
  `schema_hash`. The tables live in the native browser store next to the session tables
  (`browser_session_schema.rs`) and are created and checked with them.

`driver_identity_hash` is a digest over the driver key and the epoch. Every site grant is filed under it
(`browser-grant:v2:<driver_identity_hash>:...`). The code is in `rust/crates/guard-runtime/src/browser_driver_ledger.rs`.

What ends a grant:

1. A change to the profile id or digest, the server name or the server identity is another driver key, so it has a
   fresh ledger and another hash.
2. A changed `schema_hash` for a tool the ledger already holds bumps the epoch, which ends every grant on the driver.
3. A new profiled tool when the ledger already holds `MAX_TOOLS_PER_DRIVER` (256) tools bumps the epoch and starts
   the ledger again. Tools are never evicted silently, so no tool's schema stops being watched while a grant stands.

A new profiled tool below the cap joins the ledger without ending anything. A tool the driver profile does not map
is never covered by a site grant and never written to the ledger.

Grants are signed policy decisions, so ending one never deletes or re-signs its row. The old selector stops matching
any call, and the row runs out at its own expiry.

## Known limit: calls without a schema hash

A call that carries no schema hash never writes to the ledger and never counts as seen. It may use a grant only
through the identity match: the driver key and the current epoch. A schema change on such a call goes unnoticed until
a call of that tool arrives with a schema hash, which then ends the grants as above. This is a known gap, not an
assumption that the schema is unchanged.

## Consequences

- The hook needs the profile id and digest of the driver that matched, and records each profiled call before it asks
  for a grant. The evaluation order work (BP-T065) wires that call.
- A schema change ends grants for the whole driver, not only the changed tool. This asks the user again more often
  than a per-tool rule would, and is the safer default.
