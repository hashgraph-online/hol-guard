# Managed private Python setup

This P3/P4 milestone adds native interpreter setup and full-build binding. It does not complete the upgrade workflow: transactional switching, data preflight, catalog refresh, maintenance, public CLI/HTTP/UI controls, and installed/frozen qualification remain required by the [upgrade plan](CIGAR_UPGRADE_PLAN.md).

## Build and installation identity

`InterpreterBinding` identifies the complete CPython distribution: build ID, Python version, platform, source revision, exact archive hash/length, complete materialized tree hash/count/length, and executable hash. Catalog revision, download spelling and qualification receipts can change without replacing the same bytes.

Private Python uses an immutable binding-derived slot under `context-assistance/python/<slot>/python`. SDK installations using it have a distinct v3 physical slot and `guard-cigar-bundle-approval.v3`. A changed standard library changes the installation identity even when the Python executable stays identical.

The interpreter registry's v2 record has a home-local, domain-separated authenticated receipt. It binds the exact approved build, original catalog checkpoint, producer Guard binary, installation paths and observed interpreter facts. Catalog omission preserves an installed build; known withdrawal or identity reuse refuses it. This receipt cannot authenticate a remote catalog or authorize a new SDK installation.

External interpreter v1 records and SDK v1/v2 records retain their serialized form and existing slot identities. Optional new fields are omitted when absent. The native registry never silently rewrites them. An external registration request cannot register a path or symlink alias into the managed Python namespaces.

## Native preparation contract

The existing versions dispatcher accepts an opaque-ID request:

```json
{"action":"setup_interpreter","job_id":"setup-python-1","build_id":"cpython-3_14_10-20261026-darwin-arm64"}
```

The native owner chooses the profile, platform, paths and pinned URL. A trusted **Guard-qualified** interpreter build is required. The bundled catalog still records CPython and CIGAR as `upstream_only`; the request therefore refuses ordinary setup until their release qualifications are supplied. Test catalogs use explicit test-only signing keys and do not change that policy.

Python setup and SDK installation share one preparation controller and cross-process lease. Their combined job history is bounded to 32 records. Repeated requests converge; reusing an ID for another build or operation refuses. Progress, cancellation and recovery use the same native versions controls. Listing reads private metadata, never Python or SDK code.

Setup has a 120-second deadline, durable cancellation intent, disk checks, bounded archive parsing and exclusive staging. It verifies all distribution bytes, probes the actual isolated interpreter, and authenticates the completed installation before publishing readiness. Downloads use native network policy and pinned public peers; only the exact catalog URL and the named GitHub release-assets redirect are accepted. Explicit local operator import provides an offline archive path. Browser requests cannot supply paths, URLs, hashes or qualification claims.

Publication creates a reusable interpreter, without selecting or enabling CIGAR. Existing compatible interpreters can serve subsequent SDK builds. Lost replies recover from the actual authenticated installation and verified tree without replaying an interpreter probe. Cleanup preserves registered references, rejects unknown ownership/links, and keeps its ownership marker through bounded partial cleanup. Ambiguous outcomes remain `recovery_required`.

## Integrity and cost

Every owner process verifies the full private interpreter tree before first use. An opaque in-memory snapshot then checks every file and directory's device, inode, owner, mode, link count, size, modification time and change time before reuse. This cache is excluded from serialization and cannot be supplied through installation JSON.

The metadata shortcut is restricted to same-device APFS trees with nanosecond change times. Unknown/coarse filesystems retain full-byte verification. The distinction follows Apple's documented [timestamp granularity](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/VolumeFormatComparison/VolumeFormatComparison.html). Restoring file length and modification time does not revive changed code. A new process has no cached proof and verifies the bytes again.

The maintainer `check_python` example measures these checks without launching Python. Local source-build timings are diagnostic evidence, not installed/frozen or cross-platform performance qualification.

## Evidence and limits

[Managed interpreter evidence](evidence/receipts.json) records exact executable/source identities and tests. The real macOS arm64 workflow prepares CPython 3.14.10, installs the exact published CIGAR 0.14.1/protobuf wheels, checks graph/sharing/persistence/execution support, starts and stops the verified runtime, reuses the installation, and recovers a lost publication reply without a probe. It refuses a modified standard library while preserving its unchanged executable and user preferences.

The earlier CPython 3.14.7 installation and current-runtime cancellation tests remain covered. The current-runtime fixture uses explicitly enrolled final 0.14.1 bytes; it does not substitute for the missing original b47380 candidate or prove a newer CIGAR release upgrade.

Native Python download routing is implemented and its redirect refusal is tested; this milestone's real Python setup imports the exact archive offline. A separate live native interpreter-download qualification remains outstanding. The full CLI/HTTP/Versions UI, discovery, bounded history/environment pruning, persistent withdrawal ledger, supported data transitions and serialized switch/rollback are also outstanding. No production catalog signer/feed or additional-platform qualification was invented.
