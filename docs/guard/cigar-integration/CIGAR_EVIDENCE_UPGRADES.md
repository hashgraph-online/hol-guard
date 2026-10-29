# Evidence upgrade preflight

Guard must preserve reviewed evidence without restoring old CIGAR authority.
The P5 implementation inventories protected evidence, plans compatibility and
prepares authenticated, isolated data generations. See [prepared evidence](CIGAR_PREPARED_EVIDENCE.md) for the implemented semantic transfer and recovery path. Selection and complete lifecycle coordination remain P6 work.

## Storage inventory

| Store | Owner and format | Upgrade treatment |
| --- | --- | --- |
| Reviewed notes, source-ID basis, revision and expiry | Guard manifest schema 1 | Validate bounded records; preserve text, deletion state and original retention; readmit only under fresh current grants. |
| Broker database and rollback journal | CIGAR, opaque `sqlite-checkpoint.v1` | Keep the prior checkpoint. A matching storage label alone never establishes cross-producer compatibility. No undocumented SQL or raw database migration. |
| Granted roots, admitted files, principals, pairings, contexts and handoffs | Current native actor | Rebuild after a switch with new authority. Never include in a backup or treat an inventory digest as a permission. |
| Context history and receipts | Actor memory, with original producer labels | Do not rewrite historical labels or promote entries to current authority. Durable history migration is not introduced here. |
| Guard execution approvals | Guard approval system | Outside CIGAR data preparation; Allow once and Always allow keep their existing contracts. |

The cache remains bounded to eight slots and 528 MiB. Each protected slot has a
128 KiB manifest limit, a 32 MiB database limit and a 33 MiB journal limit.
Inspection uses pinned private directories and the existing no-link,
single-owner bounded readers. It does not run Python, query SQLite, scan a
project, sweep expired data or change a saved preference.

`EvidenceUpgradeInventory` is native-constructed and has no deserializer. Its
serialized report contains opaque slot IDs, schema/status, byte counts, note
counts/versions, expiry and active ownership. It does not contain note bodies,
source-ID basis or project paths. Its snapshot digest covers protected manifest
bytes and SDK-file identity/timestamps. Active snapshots require a fresh check
after quiescence; a timestamp is not an SDK authority or a consistency proof
for a running writer.

`EvidenceUpgradeProducer` combines the exact release/profile, SDK/dependency
locks, worker/tree and complete interpreter identity. Its native constructor
refuses an approval inconsistent with those release facts. A changed private
standard library requires a fresh producer even if the executable is unchanged.
Catalog origins and qualification receipts do not themselves replace a producer.

## Preflight result

| Situation | Classification and plan |
| --- | --- |
| Memory mode or absent saved data | Readable; rebuild ephemeral state and preserve existing saved data. |
| Valid saved data and the exact same producer | Readable; compatible checkpoint reuse still requires a fresh safe-boundary check. |
| Different supported producer and valid Guard schema | Migratable through a fresh broker plus validated Guard-note readmission. A prepared generation is required before switching. |
| Unknown/newer schema or unresolved write | Unknown; preserve data and refuse until supported recovery/preparation exists. |
| Corrupt record, missing requested feature, or insufficient bounded cache capacity | Incompatible; explicit refusal with prior data retained. |

The report includes feature differences, retained bytes, conservative additional
checkpoint/journal/manifest space and slot requirements, capacity, quiescent
recheck and prepared-copy requirements. It never deletes old slots to make the
estimate fit and never lengthens retention. Actual free-disk and generation
ownership checks still belong to preparation. A migratable report is a plan,
not evidence that migration has run or permission to switch.

## Work still required

Wire the implemented durable prepared generations into lifecycle jobs and the
serialized switch/rollback owner. Semantic transfer already preserves reviewed
provenance/expiry and requires fresh target source admission. New slots bind
the exact producer; legacy worker-keyed slots are accepted only with the exact
app/workspace namespace and verified backing SDK. The enrolled producer model
preserves candidate provenance without inventing a public release identity.
A global inventory does not authorize reading or combining notes across scopes.
Keep unmapped/inactive scopes and their required SDK files protected, and refuse
unsupported formats.

Wire fresh inventory/preflight into the serialized P6 switch owner, including
settings/generation conflicts, active-writer quiescence, retained last-good data,
crash recovery and user-visible recovery choices. No current runtime selection,
enablement, source/app scope or approval decision is changed by this module.

See [evidence](evidence/upgrades-requalification-20261026.json) for native
metadata-only fixtures. The recorded same-SDK cross-Python data round trip includes a target edit and
removal. A real newer SDK transition, committed runtime rollback, and
installed/frozen/platform validation remain unverified.
