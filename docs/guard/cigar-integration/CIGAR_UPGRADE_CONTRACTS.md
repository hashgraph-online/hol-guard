# Modular CIGAR upgrade contracts

Status: native contract implementation started 2026-10-26. This document describes ownership and lifecycle; it is not a claim that an installer or user-facing updater is delivered.

## Compatibility and build identity

guard-cigar-release owns strict catalog, identity, adapter and switch-journal types. An exact build binds SDK version, independent core version, source commit and release-manifest digest. PEP 440 determines version ordering; different build identities with equal versions are replacements, not no-ops. A reused build ID with different identity is an error.

The initial shipped adapter is guard-cigar-python-sdk-v1 revision 1. It normalizes the current local graph, view, broker, persistence and execution APIs; its guard contract, SDK API revision, worker/broker protocols, storage format and final CPython 3.14 boundary cannot be expanded by downloaded catalog data.

The catalog is the sole active release-data source. Compiled bundled data is trusted through the Guard distribution. Remote/offline data must verify an Ed25519 signature over the domain-separated exact payload bytes against a Guard-authorized catalog key. Reject unknown/revoked/inactive keys, expired/future-issued payloads, duplicate JSON fields, lower revisions, conflicting payloads at the same revision and oversized inputs. Keys supplied inside an archive or import are not trusted. New installation, interpreter setup and re-verification require current catalog authority; owner-verified installed selections follow the separate offline execution policy, known withdrawal checks and fresh protected-artifact/interpreter/adapter verification.

Preparation resolves compatibility, exact wheels/dependencies and installed-tree identity. Activation additionally requires Guard qualification for the platform and requested features, then real protected-artifact/interpreter/handshake checks. Upstream qualification is displayed separately. No production signing key or remote feed is invented in this work.

## Immutable bundles and adapter launch

The existing -I -S -B bridge path accepts a protected site-packages directory directly. Prefer a native, bounded, deterministic extraction of supported locked wheels into a fresh private bundle over invoking pip, resolving dependencies online, running source builds or updating a venv in place. The selected independently verified final CPython 3.14 interpreter stays separate from Guard's host Python. Unsupported wheel layouts/ABI/dependency sets must refuse explicitly.

A release-entry generator must calculate the existing guard-cigar-package-tree.v1 digest from the exact dependency and SDK wheel files. Artifact inspection binds that entire installed tree, the worker, Python executable, SDK/core/protocol identities and shipped adapter. Changing a version label or copying an official worker beside modified SDK code is insufficient. A separate manifest binds the slot to exact release, dependency, interpreter and qualification identities.

Legacy v1 local approvals retain their historical exact-version contract from the bundled legacy profile and their existing operator-approved tree fingerprints. They do not become public stable approvals. Versioned approval v2 includes a ReleaseBinding that must match fresh trusted catalog resolution.

## Registry, jobs and transport

An installation v2 record composes immutable release/adapter identity, protected runtime selection and bundle approval, real interpreter facts, provenance and qualification receipt. Legacy v1 records remain readable and keep their IDs. Listing reads bounded metadata and never executes Python. Active, selected, last-good and in-use slots cannot be removed; external operator environments are never deleted.

Native operator requests identify a release/installation and carry an idempotency key plus expected settings/selection revision. Paths, hashes, trust keys and arbitrary package indexes are excluded from HTTP/MCP administration requests. Existing explicit local enrollment remains an advanced operator command. Paired context consumers cannot perform runtime administration.

Durable jobs report preparing, acquiring, extracting, verifying, ready, switching, recovering and terminal outcomes. Preparation cancellation leaves the selected installation untouched. Cancellation or a lost reply after cutover triggers journal reconciliation instead of a blind retry. Remote checks respect effective policy and bounded origin/size/time limits.

## Switch and data contract

A switch journal records source/target installation and exact builds, expected generation/settings digest, previous on/off intent, explicitly authorized target activation, data generations, phase and cancellation. It contains no grants, credentials or execution approvals.

The initial data choices are memory rebuild, proven read/write-compatible reuse and an independently prepared copy. Unknown or unsupported formats refuse before stopping the old runtime. Copied data restores evidence, never authority.

| Durable phase | Expected selection | Recovery |
| --- | --- | --- |
| Prepared | Previous | Keep previous intact; cancel preparation safely |
| OldRuntimeStopped | Previous | Restore previous only while eligible |
| SelectionCommitted | Target | Reverify target, or restore an eligible previous build |
| TargetHealthy | Target | Finish the selection/last-good commit |
| Completed | Target | No new switch |
| RollbackSelected | Previous | Reverify previous before declaring rollback complete |
| RolledBack | Previous | No new switch |
| RecoveryRequired | Either | Reconcile protected records; no blind execution |

Native persistence must reconcile both sides of every write boundary before using these decisions. An ambiguous or unrelated selection requires explicit recovery. Withdrawn bytes cannot become an automatic rollback.

Prepare replacement bytes and required proofs while current work continues. Cut over under one lifecycle lock with stale-generation rejection and a bounded quiescent boundary. Preserve Guard approvals and saved off/on/source/app intent. Keep Guard-owned pairing/consent only where the same live authenticated client and scopes can be revalidated; re-create SDK graphs, snapshots, broker grants and authority epochs. Never promise a transparent reconnect without proving that native rebind path. Do not persist ephemeral credentials merely to avoid a reconnect.

Scoped deletion now uses a separately authenticated native cache-attribution index and durable intent. Unknown legacy entries refuse before mutation. Native Clear notes/Withdraw preserve unrelated live scopes; an authenticated access-reduction resume works while off and does not restore grants. See [scoped deletion](CIGAR_SCOPED_DELETION.md) for exact local SDK evidence and remaining qualification.

Operator administration negotiates context-assistance-versions-v1, canonical generation strings and explicit reconnect consent. Bounded unified job metadata routes to native preparation/live-switch owners. CLI/authenticated HTTP remain framing; version requests enter the optional-work lane. See [operator controls](CIGAR_UPDATE_OPERATOR_CONTROLS.md) for exact contracts, acceptance and remaining policy/catalog/UI work.

Authenticated catalog distribution now uses a separately configured public-root authority, profile-bound retained MAC, immutable SDK/interpreter byte history and cumulative withdrawals. One native resolver serves fresh preparation and offline installed-receipt resolution with distinct trust rules. Catalog import leaves runtime selection, enabled state, preferences and grants unchanged. Only the import action receives the larger bounded resident frame. See [authenticated catalogs](CIGAR_AUTHENTICATED_CATALOGS.md) for exact roots/import contracts and no-interruption re-verification evidence. [Bounded native refresh](CIGAR_CATALOG_REFRESH.md) now owns explicit feed configuration, background cancellation/deadlines and current signed publication without activation. Only opaque job IDs enter resident refresh requests; progress cannot become trust authority or restore older metadata. [Atomic first publication](CIGAR_ATOMIC_CATALOG_STORAGE.md) now publishes a new key/cache pair together, preserves existing complete flat catalogs and reconciles matching authenticated state after unknown outcomes. Nine process exits cover the publication boundaries; committed loss/tamper never permits key regeneration or ledger reset. Power/disk-loss and production feed/trust qualification remain incomplete.

## Verification boundaries

Synthetic future builds prove contract routing and data-only extensibility. Only exact real artifact tests qualify installation, runtime switching and platform behavior. The old candidate-to-final same-version build transition is real and available; a nonexistent newer version must not be relabeled as qualified. Native/transport/UI/installed/frozen evidence and performance/cleanup checks remain separate, with baseline repository failures retained.

Ordinary settings opt-in validates exact installed bytes under the shared profile lifecycle lease before taking the short config writer lock. Final publication checks home identity and exact captured bytes; concurrent edits refuse rather than replay. Explicit Stop remains independent and advances a native intent fence even while already off, rejecting a previously prepared enable. Saving enabled intent does not start the SDK. See [settings opt-in](CIGAR_SETTINGS_OPT_IN.md) for the real catalog-import regression, restored busy diagnostics and the precise local evidence scope.

[Native update preferences](CIGAR_UPDATE_PREFERENCES.md) now live outside serving SDK configuration. One native owner reads current machine restrictions/locked paths and publishes the separate profile table through exact-revision protected CAS. Pins identify exact catalog builds, including same-version replacements; preview permission is a consent ceiling. Supported new selection paths enforce both while existing healthy actors keep serving. Local bytes and policy-only changes invalidate prepared choices before cutover. Manual/notify intent is saved without automatic refresh, preparation, selection or activation; notification UI and retention/removal remain required. CLI/HTTP retain the existing operator/approval boundary.

[Cold reviewed-data preparation](CIGAR_COLD_DATA_PREPARATION.md) now separates MAC-sealed deferred notes from live SDK authority. Closed-store export requires complete native attribution and actual source SDK provenance without rebuilding its native source catalog. Ready deferred data can accompany a disabled SDK/data-pair transaction, but future app access requires fresh source bytes, current note permission and the exact target generation. Carry preserves original producer/expiry; reduced retention is durable and participates in identity. Scoped erasure follows ancestral data without treating its audit key as an immediate-parent file. The bounded public off-state job and full admission/data-choice matrix remain required.

[Disabled selection and rollback](CIGAR_OFF_STATE_SELECTION.md) now reuse the existing bounded job/lease/transaction contract when a readable source installation is already selected. Complete authenticated generation digests and a post-source-close cache inventory fence cutover. Temporary SDK cancellation is isolated from the job token. Commit publishes only the coupled disabled SDK/data pair; fresh app/source/note authority is still required after a separate explicit enable. Healthy disabled completion metadata can reconcile without any SDK activation or mutation replay. Initial/unavailable-source choices, the complete crash-phase matrix and ordinary-settings selection routing remain required.

The [ordinary-settings guard](CIGAR_SETTINGS_SELECTION_GUARD.md) refuses a nonempty-to-different-nonempty runtime ID replacement before lifecycle/SDK/publication effects. Its native error code and validation instruction preserve existing settings-client semantics. The dedicated coupled selection owner remains the replacement path. Initial/reset/clearing/data-choice flows remain distinct required work; no complete selection-routing claim is made.

The [initial selection protocol](CIGAR_INITIAL_SELECTION.md) uses a separately authenticated marker rather than a fictional previous SDK/data pointer. Its native empty-data proof is profile-identity-bound; the actual target record has no last-good entry. One bounded operator worker commits while remaining off. Unpublished cancellation and Healthy completion acknowledgement can be reconciled; earlier committed recovery and existing-data choices remain required.

[Initial recovery](CIGAR_INITIAL_RECOVERY.md) now verifies an already committed, exact disabled target through the bounded worker. Each explicit attempt has separate budget/cancellation identity; progress never grants eligibility. Old cancellation cannot veto a new explicit attempt, and a stale native cancel cannot interrupt a newer one. Preferences, native generation and app scopes are not rewritten/restored. Current public generation strings preserve full precision.
