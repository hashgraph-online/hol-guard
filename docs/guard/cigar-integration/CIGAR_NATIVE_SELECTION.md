# Native SDK/data selection and recovery

The native profile owner now records exact SDK/data pairs, publishes selection
with a write-ahead journal, and connects fresh Service activation to the recorded
data generation. These P6 primitives now support the [live coordinator](CIGAR_SERVICE_SWITCHING.md),
[explicit rollback](CIGAR_ROLLBACK_RECOVERY.md) and [known-failure source reconstruction](CIGAR_SOURCE_RESTORATION.md).
Complete crash/privacy qualification and the public workflow remain unfinished.

## Identity and protected ownership

`guard-cigar-selection.v2` records current, retained last-good and in-flight
SDK/data pairs. An installation stamp binds the opaque installation ID, local
installation and approval hashes, and complete measured producer fingerprint.
Catalog origins retain their full independent SDK/core/source/manifest/profile
identity. Enrolled origins retain their verified SDK/core/adapter labels and
exact local byte identity; they contain no inferred public build ID, upstream
revision or release manifest. The older pure v1 journal contract remains intact.

Stamps come from a loaded native installation and a real verified runtime.
Installation receipt refresh bookkeeping is excluded from physical selection
identity; it cannot make unchanged installed bytes a new data producer. A fresh
activation still resolves the protected installation receipt, checks current
catalog eligibility and repeats the required actual runtime checks.

The owner holds the same profile preparation lease as SDK and interpreter jobs.
It excludes competing preparation/finalization and full saved-data removal.
Short metadata/config effects share the existing protected settings writer
lock; target SDK startup and source-file admission stay outside that writer.
The journal is HMAC-sealed to a canonical profile with a separate local lifecycle
key. That key is distinct from installation, catalog and execution-approval keys.
Only explicit native initialization provisions it. No browser-supplied paths,
hashes, keys or readiness facts enter the owner API.

Fixed journal/key names use pinned descriptor-relative I/O, private single-link
files, byte limits, exclusive staging, file sync, atomic rename and directory
sync. The writer checks expected record/key bytes and current config. Read-only
config/record modes and ACL refusals remain effective. Orphan cleanup recognizes
only lifecycle staging names and validates the entire bounded batch before
deleting: at most 32 files, at most 4 MiB total, and at most 4096 directory entries.
Unrelated names, links and unsafe ownership/modes are never repaired or removed.

## Publication and recovery

The settings snapshot changes only the runtime ID. All other preferences,
enablement, source choices and unrelated TOML remain intact. Before any config
effect, the owner persists `commit_intent`. It then compares/publishes the exact
settings and records the committed SDK/data pair. A failure after either rename
surfaces `switch_commit_outcome_unknown`; the caller must reopen and inspect the
protected state rather than replaying or reversing a write from memory.

Last-good moves only after fresh target verification and healthy/completed
publication. Native generation-retention references derive from current,
last-good and pending pointers. They are metadata, never scope-read authority;
immediate job cleanup consumes them while complete lineage/capacity handling remains required.

Fresh Service verification now reconciles a compatible interrupted transaction
and binds the matching ready generation and exact producer before creating an
actor. A config rename with only `commit_intent` on disk can finish through this
path after actual installed SDK and feature checks. If config still names the
previous installation, compatible precommit intent can be cancelled/reconciled
without overwriting preferences. Terminal selections allow subsequent ordinary
preference changes. Unexpected target settings or ambiguous in-flight config refuse.

A later disabled preference wins. Recovery can identify which recorded data
belongs to the selected SDK while preserving opt-out; it never writes enabled
preferences or starts an actor on its own. No journal grants an app/workspace,
restores an SDK context or recreates an agent session. Restart requires fresh
workspace admission and normal pairing. The live controller can reconstruct native
scope intent after a known unpublished failure, or explicitly prepare last-good
with current reviewed data; neither operation revives SDK authority from this journal.

## Deletion and qualification limits

Explicit full saved-data deletion now takes the preparation lease, removes all
saved/generation data and clears the corresponding lifecycle references/key.
It can repair corrupt journal/key content without trusting either and preserves
settings/opt-out. It refuses while another preparation owner is live. The
controller must still cancel/drain that owner, and per-scope deletion must still
cover every retained/prepared copy before exposing upgrade controls.

The real-SDK test exercises v1 enrollment of the exact final 0.14.1 artifacts,
native exact-wheel target publication, live capture, semantic note preparation,
bounded old-actor shutdown, native config/journal commit, an injected lost
settings-rename acknowledgement and fresh Service recovery. Fresh workspace
admission must recover the reviewed note; old scope/agent authority must be
absent. Explicit full deletion must repair corrupt selection metadata while
preserving Stop and all other preferences. This is a local macOS arm64 source
test, with external CPython 3.14.7/3.14.10. It does not inject process death,
exercise a live Service cutover controller, qualify original b47380 bytes, prove
a genuinely newer SDK release, or qualify installed/frozen/other-platform use.

The later live-coordinator milestones cover bounded jobs, native epoch/observation
revocation, current-data rollback, memory transfer and selected known-failure recovery.
Remaining P6 work includes every crash/unknown/cleanup boundary, retained-generation
restoration, durable erasure and per-scope retained-copy deletion, inactive-data
readmission, complete lineage/capacity handling, accepted feature differences and
a narrow final boundary without workspace I/O on the old actor. P7/P8 controls and P9/P10 qualification,
including production catalog trust/hosting, remain required. Production unused
entry-point warnings honestly identify the unconnected switch construction path.

See [engine preparation](CIGAR_ENGINE_PREPARATION.md),
[settings lane](CIGAR_CONFIG_COMMIT_LANE.md), and the exact
[selection evidence](evidence/upgrades-native-selection-20261027.json).
