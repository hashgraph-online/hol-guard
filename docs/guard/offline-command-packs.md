# Offline command protection data

Ordinary community protection does not require a Cloud subscription. Existing
enable controls prepare authenticated policy automatically when online. A
complete active snapshot continues to protect commands during an outage;
enabling uncached policy offline reports unavailable and retains current controls.
Command hooks and decision leases do not perform these downloads.

The explicit control commands also support preparing the complete public library:

```sh
hol-guard command controls prefetch
hol-guard command controls export-offline /path/to/new-export-directory
hol-guard command controls import-offline /path/to/export-directory
hol-guard command controls cleanup-cache --maximum-bytes 536870912
```

The default authority is the authenticated installed release. An export is a
portable directory containing `root.json`, `objects/` and `archives/`. It contains
only public assets reachable from that release, never device controls, saved
approvals, credentials or private inventory. Export generates the inventory
automatically and requires a new destination directory. An interrupted export is
incomplete and cannot be imported successfully.

Offline import requires the exact Root bytes authenticated by the destination's
installed package: source, native engine and content identity must match. A
newer package can use an identical Root; the export does not assert a package
version or grant update authority. Installed publication `0.0` is not remote
freshness. Import and prefetch only stage data; normal activation still enforces
protected lineage, versions, epochs and approvals.

`--remote` selects the current publication through the existing verified publisher
factory. Remote import requires that independently verified, currently fresh
authority and the exact exported Root. It therefore needs the authority lookup
online; this option does not turn installed metadata or an unsigned export into
a fresh air-gap update. Use the matching installed-release export for fully
offline import. Existing active remote policy retains the established offline
continuity and explicit security-observation behavior.

Rust traverses and verifies the complete object graph, page ownership/counts,
digests, lengths, policy metadata bindings and native policy admission. It also
checks stored ZIP headers, CRCs, member digests and names before ingestion.
Traversal, symlink, duplicate-member, compression and expansion tricks fail
admission. Python performs transport and file/archive IO for native-selected
objects; it has no alternate planner or fallback policy algorithm.

Cleanup runs periodically outside decisions and can also be requested explicitly.
It authenticates the current activation and pending records and retains their
native read sets, including core protection. A prepared preview retains its
shared cache lease through the activation draft; a live transfer prevents
eviction. Process exit releases that lease. Under the exclusive control and
cache fences, native cleanup plans first and removes only unreferenced immutable
objects, inactive sets, transfer archives and interrupted temporary writes.
Missing/corrupt authority or pins stop cleanup. It never deletes protected floors
or changes controls or saved approvals. If required protection exceeds the
requested budget, cleanup reports `over_budget` and retains that protection.
The maximum accepted budget remains 512 MiB; `0` collects every unpinned object.
