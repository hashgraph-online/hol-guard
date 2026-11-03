# CIGAR upgrades: implementation map and execution goal

Current acceptance clarified 2026-10-28: the user is satisfied with 80–90% dynamic infrastructure because 0.14.1 is the newest available build; application logic must not pin a CIGAR SDK release. [The current readiness/audit](CIGAR_DYNAMIC_INFRASTRUCTURE.md) records an approximately 85% engineering estimate, zero production0.14.x version gates, data-driven exact catalog/lock/qualification additions and passing current/synthetic contracts. The core target is met. The full P0–P10 checklist below remains the extended release/hardening roadmap, not a claim of complete production/newer-release/platform qualification.

Status: execution authorized and goal activated 2026-10-26. Follow [the reassessment](CIGAR_UPGRADE_REASSESSMENT.md), [execution goal](CIGAR_UPGRADE_GOAL.md), and [separate execution log](CIGAR_UPGRADE_EXECUTION_LOG.md). The reassessment supersedes stale publication and version-only build assumptions below. Model configuration remains a session control; publication and live-preview changes remain separate actions.

Requested future executor: **GPT-6.1 Sol (`gpt-6.1-sol`), reasoning effort `max`**. Carry these settings into the execution session; recording them in a goal does not configure the executor. No token budget has been requested.

Implementation checkpoint 2026-10-26: authenticated catalogs, exact SDK/interpreter identities, immutable private CPython setup, bounded preparation jobs, independent SDK/core/release labels and installed-slot qualification refresh are implemented locally. See [requalification](CIGAR_RELEASE_REQUALIFICATION.md) and [evidence preflight](CIGAR_EVIDENCE_UPGRADES.md). P5 inventory/preflight has started; prepared evidence generations, transactional switching/rollback, complete operator/UI flows and final installed/frozen/platform qualification remain unfinished. The authorized reassessment includes private CPython installation; the earlier scope sentence below is historical. No automatic selection, enablement, live-preview change or production catalog qualification follows from this checkpoint.

Implementation checkpoint 2026-10-27: [prepared evidence generations](CIGAR_PREPARED_EVIDENCE.md) now support authenticated reload, semantic SDK note transfer, original retention, interrupted-commit recovery and reverse data preparation after a new edit/removal. These native data primitives preserve the current runtime; they are not yet a serialized runtime switch or public update workflow. Verified enrolled legacy producers now preserve their independent candidate/byte identity, with no inferred public source revision. The native settings writer has a protected commit lane; P6 actor/selection/data journaling, rollback and lifecycle coordination remain required before general upgrade/rollback readiness. See [settings commit lane](CIGAR_CONFIG_COMMIT_LANE.md). Native [engine preparation and admission barriers](CIGAR_ENGINE_PREPARATION.md) now preserve live scope intent and history while preparing fresh SDK state beside the old actor; the [native profile selection owner](CIGAR_NATIVE_SELECTION.md) now journals exact SDK/data pairs and connects fresh Service activation to compatible interrupted-commit recovery. Central live switch jobs, all recovery effects and full rollback remain unfinished.

Implementation checkpoint 2026-10-27: the [live native Service switch coordinator](CIGAR_SERVICE_SWITCHING.md) now prepares beside the serving actor, cancels/removes Ready copies, enforces explicit reconnect consent, revokes native authority at the admission boundary and attaches the target only after journal/config/health success. The actual finalSDK0.14.1 test passed across external Python3.14.7/3.14.10 while the source served257 requests. This is not newer-SDK or full P6 acceptance: known-failure restoration, latest-data rollback, complete privacy/process-loss recovery and public controls remain unfinished. The full P0–P10 goal stays active.

Implementation checkpoint 2026-10-27: [memory-only reviewed notes](CIGAR_MEMORY_NOTES.md) now use a native SDK-proven in-memory handoff, with no saved-evidence store. The actual two-app live switch preserves complete note digests and original expiry, refuses a candidate made stale by a new reviewed edit, and keeps the source serving through preparation/cancellation. SQLite acceptance also passes after sharing provenance verification. Rollback/recovery, retained-copy privacy, public controls and full P9/P10 qualification remain unfinished.

Implementation checkpoint 2026-10-27: [explicit last-good rollback and completion recovery](CIGAR_ROLLBACK_RECOVERY.md) now use the live transaction engine. Actual saved/memory round trips preserve current reviewed data and original expiry without resurrecting a removed note. A read-only completion journal leaves the published SDK serving and is reconciled without restart. Automatic restoration on known pre-publication failure, complete crash/privacy handling, public controls and final qualification remain unfinished.

Implementation checkpoint 2026-10-27: [automatic safe source reconstruction](CIGAR_SOURCE_RESTORATION.md) now handles known unpublished cutover failures with a native-only boundary snapshot, fresh SDK authority, exact settings/policy checks, cleanup acknowledgements and a separate bounded restoration cancellation budget. Actual saved/memory tests cover readonly commit failure, post-commit cancellation and Stop during restoration. Original notes/expiry/history survive while old contexts/agents/epochs remain revoked. Complete crash/cleanup/privacy handling, retained-generation recovery, public controls and final qualification remain required.

Implementation checkpoint 2026-10-27: [cleanup-pending profile ownership](CIGAR_CLEANUP_OWNERSHIP.md) now retains the lifecycle lease for cancelled candidate, stopped source and failed reconstructed-source actors until SDK/private-state cleanup acknowledges. Actual destructor-gated saved-mode tests cover all three roles, source service during candidate cancellation, cross-Service exclusion, deferred data pruning and Stop without reactivation. Status and Stop stay independent while pending; full crash/privacy/public-workflow qualification remains unfinished.

Implementation checkpoint 2026-10-27: [prepared original-SDK recovery](CIGAR_PREPARED_RECOVERY.md) now moves fresh source verification into background preparation, with no user cache/scope opened, before Ready and source shutdown. Actual recovery from an edited selected generation preserves current data/expiry/history, last-good and fresh authority; the source serves context during verification. The initial deadline failure and near-limit diagnostic pass are retained, and the later local recovery path falls from29.6s to5.4s with unchanged budgets. Memory and all three cleanup roles are rechecked. Full crash/privacy/public/platform qualification remains unfinished.

Implementation checkpoint 2026-10-27: [durable full saved-data deletion](CIGAR_DURABLE_ERASURE.md) now clears the legacy source copy as well as selected/retained/prepared generations, keeps a private admission-blocking intent across partial deletion and resumes only on explicit retry. The real final0.14.1 upgrade/interruption/retry case passes without changing preferences or enabling disabled users. Per-scope retained-copy deletion and the remaining P6/public/platform matrix remain unfinished.

Implementation checkpoint 2026-10-27: [scoped copy-erasure primitives](CIGAR_SCOPE_ERASURE_PRIMITIVES.md) now follow authenticated lineage, remove known retained/prepared/legacy copies and staging text, preserve unrelated scope leases, and support a sealed explicit-resume intent. Context tests pass 88 on stable/1.88 and native selection tests pass 45. User-facing Clear notes/Withdraw/resume integration, complete legacy attribution and actual scoped SDK acceptance remain unfinished; this is not full per-scope privacy acceptance.

Implementation checkpoint 2026-10-28 UTC: [scoped deletion and off-state recovery](CIGAR_SCOPED_DELETION.md) now connect Clear notes/Withdraw to authenticated, complete cache attribution and retained/prepared-copy erasure. Actual saved and memory-only SDK cases preserve unrelated apps/workspaces and serving SDK state, resume interrupted deletion while disabled, and prove no note/grant resurrection after explicit restart. Unknown legacy entries refuse before mutation. Public update controls/UI and the remaining P6/P9/P10 matrix remain unfinished.

Implementation checkpoint 2026-10-28 UTC: [operator update controls](CIGAR_UPDATE_OPERATOR_CONTROLS.md) now expose native preparation, acknowledged commit, last-good rollback and unified jobs through thin CLI/authenticated HTTP framing. A real SDK case through bound native request envelopes preserves latest reviewed data across rollback. Python 67, Service 17, daemon-route 10 and optional-lane 15 tests pass. P7 remains partial: pin/policy/catalog refresh/import, off-state selection/removal, P8 UI and the remaining P6/P9/P10 matrix are unfinished.

Implementation checkpoint 2026-10-28 UTC: [authenticated offline catalog distribution](CIGAR_AUTHENTICATED_CATALOGS.md) now feeds one native resolver for release listing, install/re-verification, private Python preparation, artifact imports and installed receipts. Separately configured public roots, replay/identity history and permanent withdrawals protect retained data. A real final 0.14.1 SDK case imports a catalog and re-verifies the target through the normal install action while the source actor, preferences, generation and reviewed notes remain intact, then explicitly switches and rolls back with latest data. Registry 107, Service 17, protected configuration 19, off-data 10, routes 10 and Python 73 tests pass. P7 remains partial: remote refresh/trust hosting, first-import recovery, pin/update/retention policy, off-state selection/removal, P8 UI and remaining P6/P9/P10 qualification are unfinished.

Implementation checkpoint 2026-10-28 UTC: [bounded native catalog refresh](CIGAR_CATALOG_REFRESH.md) now supports an explicitly configured HTTPS feed, cancellable metadata-only background jobs, shared lifecycle ownership, current signed-catalog validation and authenticated same-cache completion recovery. The real final 0.14.1 SDK serves an existing context snapshot during a deliberately paused synthetic refresh; source/preferences/generation/reviewed notes stay intact before normal re-verification, switch and latest-data rollback. Registry 115, Service 17, protected configuration 19, route authorization 10, optional lane 15 and Python 76 pass on the recorded final source/image. Production feed/trust and first-provisioning recovery, P7 pins/policy/off-state selection/removal, P8 UI and remaining P6/P9/P10 qualification are unfinished.

Implementation checkpoint 2026-10-28 UTC: [atomic first catalog publication](CIGAR_ATOMIC_CATALOG_STORAGE.md) removes the new-profile key/cache visibility gap through one protected no-overwrite directory rename. Nine genuine subprocess exits cover six initialization and three update boundaries; retries preserve the original key/current authenticated bytes and reclaim only safe unpublished staging. Complete existing flat catalogs remain readable/refreshable without migration; committed loss/tamper still fails closed. Registry 118, config 26, Service 17 and off-state data 10 pass, and the real final0.14.1 context/refresh/re-verification/switch/rollback case passes on the same image. Power/disk-loss and remaining P6/P9 qualification, P7 policies/off-state selection/removal, production trust/feed, P8 UI and P10 installed/frozen/platform/approval/load/performance/bump evidence remain required.

Implementation checkpoint 2026-10-28 UTC: [ordinary settings opt-in](CIGAR_SETTINGS_OPT_IN.md) now verifies a managed installation outside the short config lock while retaining the shared lifecycle lease through exact-byte publication. This fixes a reproduced real final0.14.1 false-CPython refusal after catalog import. Explicit Stop changes a native intent fence even when already off, so an older prepared enable cannot overwrite it. Five new config cases and real SDK opt-in/contention/tamper/Stop cases pass; the existing live refresh/switch/latest-data rollback case passes on the same final image. P7 pin/update/notification/channel/retention policy, off-state SDK/data selection/removal, P8 UI and full P6/P9/P10 qualification remain required.

Implementation checkpoint 2026-10-28 UTC: [native update preferences and exact-build pins](CIGAR_UPDATE_PREFERENCES.md) now have a separate profile table, current machine-policy ceilings/locks, passive revisioned reads and protected CAS writes through native/CLI/approved HTTP controls. Ordinary settings selection and live preparation enforce the pin/preview rules; a local or policy-only preference change invalidates Ready. A real final0141 case preserves the serving actor/epoch/notes/current snapshot across pin writes, rejects stale cutover without source interruption, and explicitly switches under a matching pin. All three real SDK cases pass on the same final image. Notification presentation, automatic preparation, retention/removal, cold off-state SDK/data selection, P8 UI and remaining full P6/P9/P10 qualification are unfinished.

Implementation checkpoint 2026-10-28 UTC: [cold reviewed-data preparation](CIGAR_COLD_DATA_PREPARATION.md) now verifies closed stores through the source SDK and native MAC attribution, seals deferred notes with original provenance/expiry, carries them through reselection and admits them only under fresh source and note permission. A native SDK/data-pair transaction stays disabled; the real final0141 case then proves both apps, a read-denied/reopened target and scoped deletion without resurrection. The separate SDK core case proves three-generation provenance, wrong-cache/source refusal and interrupted import reconciliation without replay. Six new synthetic cases bring context tests to99 on stable/1.88. The public bounded cold-selection job, initial/unavailable-source/data-choice cases, live inactive-legacy qualification, removal, P8 UI and remaining P6/P9/P10 work remain required.

Implementation checkpoint 2026-10-28 UTC: [disabled selection and rollback](CIGAR_OFF_STATE_SELECTION.md) now use the existing bounded cancellable job and sealed SDK/data owner. Resident operator acceptance proves Ready cancellation, off-state commit without reconnect, missing completion acknowledgement recovery without SDK activation/replay, safe missing-target failure, off-state last-good rollback and fresh two-app note admission. CLI framing exposes this without a reconnect flag for the off path; native running selection still requires consent and HTTP authorization is unchanged. Initial/no-source, unavailable-source/data-choice and remaining crash recovery, ordinary settings selection routing, live inactive legacy migration, removal/retention, P8 UI and P9/P10 qualification remain required.

Implementation checkpoint 2026-10-28 UTC: [ordinary-settings selection guard](CIGAR_SETTINGS_SELECTION_GUARD.md) now refuses replacement of an existing nonempty runtime ID before SDK work or any profile publication, preserving the running actor/epoch/context and off-state preferences. It returns an actionable validation message through the unchanged settings client. Published-SDK acceptance, native config57/1 and Service19/17 SDK gated, Python92, Rust1.88 and ownership/privacy/format checks pass. Initial allocation, clearing/reset/reselection with saved data, unavailable-source choices and the rest of P7/P8/P9/P10 remain required.

Implementation checkpoint 2026-10-28 UTC: [initial selection](CIGAR_INITIAL_SELECTION.md) now prepares and commits a first SDK/data pair while remaining disabled, with authenticated empty data and no invented previous runtime. Initial, existing live-switch and disabled-switch SDK cases pass on one image; native Service20/18, configuration57/1, registry133/5 and saved-data10 pass. Earlier committed recovery, source/data choices, full initial/reset/settings routing and remaining P7–P10 acceptance are required. The first workspace deadline remains an unresolved reliability observation.

Implementation checkpoint 2026-10-28 UTC: [bounded initial recovery](CIGAR_INITIAL_RECOVERY.md) re-verifies an already committed target without enabling CIGAR or restoring app grants. Explicit retries have separate120-second budgets/cancellation identities and preserve exact generation strings. Recovery, initial, live and disabled SDK cases pass on one image; Service21/19, configuration57/1, registry138/5 and saved-data10 pass. Selected-source recovery, data choices/settings routing and remaining P7–P10 work remain required.

Implementation checkpoint 2026-10-28 UTC: P8 frontend versions transport/job contracts now have six passing assertion modules, preserving original workspace/tutorial sources. Strict scoped typechecking matches seven unchanged transitive errors; whole-dashboard TypeScript remains non-green. Panel wiring, notifications, walkthroughs, browser/accessibility acceptance and remaining P7/P9/P10 work are still required.

Implementation checkpoint 2026-10-28 UTC: [modular Versions & updates UI](CIGAR_VERSIONS_UI.md) now exposes passive host/catalog/installation metadata, preparation, explicit acknowledged selection/rollback, cancellation/recovery and update preferences. Nine assertion modules and eleven isolated fixture-browser checks pass, including delayed-reply/Stop ordering and styled390px layout. Strict wired-graph checking retains exactly13 prior shared diagnostics and no new-file errors. This is partial P8: notifications, walkthroughs, complete settings/data-choice routing and full P6/P7/P9/P10 qualification remain required. Browser fixtures are not installed HTTP/SDK acceptance.

Implementation checkpoint 2026-10-28 UTC: [owned runtime picker and update walkthrough](CIGAR_VERSIONS_ROUTING.md) now keep runtime IDs out of the ordinary draft, preserve existing lesson progress and prevent JSON key-order changes from replacing pending preferences. Fourteen isolated browser checks and focused assertion modules pass; strict checking still matches13 prior shared errors. Native initial/reset/clearing/data-choice paths, notifications and remaining full P6/P7/P9/P10 qualification stay required.

Implementation checkpoint 2026-10-28 UTC: [committed disabled-selection recovery](CIGAR_DISABLED_RECOVERY.md) now re-verifies an already committed target in the bounded native worker, preserves off/preferences/data/grants, supports explicit cancel/retry and publishes last-good only after health. Five actual final0141 SDK workflows pass on one current native image; native143/21/57/10, MSRV/format/ownership/privacy gates pass. Clippy and scoped TypeScript retain only their recorded36/13 baseline errors. Narrowing-aware Stop/settings recovery, live-selected/other durable phases and true process-loss/full release qualification remain required.

Implementation checkpoint 2026-10-28 UTC: [Stop-aware committed recovery](CIGAR_STOP_RECOVERY.md) now preserves current disabled settings for committed/healthy targets, including previously live switches after Stop. Six actual final0141 SDK workflows pass on one image; native148/22/57/10 and16 fixture-browser checks pass. Catalog maintenance now has a local CI workflow/runbook and41 Python/85 native contract checks, including three explicitly synthetic drafts. Still-enabled/other durable phases, true process loss, data choices/removal/notifications and full P9/P10 release/installed/platform/approval/performance qualification remain required.

## Outcome to build

Let a Guard user discover compatible CIGAR releases, install a chosen release into its own environment, verify it, explicitly switch to it, pin it, and return to the last working installation. Keep Context Intelligence Graph Agentic Runtime optional and preserve the existing CIGAR workspace, tutorials, source controls, application permissions, and Guard approval behavior.

A routine compatible release must be addable through one declarative release catalog, exact artifact locks, and qualification receipts. It must not require editing version strings throughout Rust, Python, and TypeScript. Guard must also accept a newer authenticated catalog without requiring a new Guard binary when its shipped adapter already supports the qualified release. A release with an incompatible SDK API, worker protocol, or storage contract requires a new qualified Guard adapter or Guard update.

The first implementation supports multiple installed CIGAR versions and one selected runtime per Guard profile. Concurrent different SDK versions for different workspaces, installing Python itself, unattended runtime switching, publishing releases, and modifying the CIGAR SDK source are separate work.

## Verified starting point

- Repository: `hol-guard-cigar-integration`; branch: `feature/integrate-cigar-0.14.1`.
- The original integration goal is complete. Preserve [EXECUTION_GOAL.md](EXECUTION_GOAL.md), its acceptance record, and its execution log as history. Use a separate goal and log for upgrades.
- The working tree already contains CIGAR workspace, activation, tutorial, browser-test, and generated dashboard changes. Record that baseline before implementation and preserve it. Do not reset, clean, or overwrite it.
- Current candidate SDK: `0.14.1`, from the local `hol-cigar-0.14.1-security` checkout at `b47380e5a5cbeaaad5a61cab3372e9e67368732f`. Its qualification does not qualify future releases.
- Current local acceptance is macOS arm64. Guard's host Python and the separately selected CIGAR Python are independent. The existing final CPython 3.14.7 installation is a valid candidate when its platform, ABI, and artifacts pass verification.
- As checked on 2026-10-26, the official [PyPI package page](https://pypi.org/project/hol-cigar/) and [GitHub release index](https://github.com/hashgraph-online/hol-cigar/releases) list `0.14.0` as the latest published release. PyPI specifies Python `>=3.14,<3.15`. The local `0.14.1` candidate is therefore newer than the currently listed public release. Recheck these sources at execution time; never interpret public `0.14.0` as an upgrade from local `0.14.1`.
- A real approved release newer than `0.14.1` has not been selected for this upgrade plan. That is a qualification dependency, not permission to invent a version or downgrade the user.

### Existing implementation and required changes

| Area | Current behavior | Upgrade work |
| --- | --- | --- |
| `rust/crates/guard-context-assistance/src/lib.rs` | Compile-time `CIGAR_VERSION = "0.14.1"` and worker protocol constant. | Resolve an exact approved release through a compatibility profile; retain strict protocol checks. |
| `.../src/artifacts.rs` | SDK release, native core, and manifest SDK release must all equal the single constant; protected package/worker bytes are fingerprinted. | Verify independent expected SDK/core/protocol identities and exact platform artifacts from the approved release. Preserve protected reads, byte limits, and revalidation. |
| `.../src/runtime.rs` | Embedded bridge; static package/protocol status fields; real interpreter probe, doctor, and synthetic compilation. | Carry the verified installation identity and adapter into launch/status; prove the capabilities requested for that release. |
| `integrations/cigar/bridge.py` | Fixed SDK imports and method signatures; executed with `-I -S` and only the verified SDK path. | Keep a thin SDK adapter behind a stable native contract; package adapters as Guard-owned embedded or verified staged resources. |
| `rust/crates/guard-runtime/src/context_assistance_registry.rs` | Operator-enrolled `local_candidate` records, at most eight; list returns Python/platform/fingerprint but no CIGAR version. No managed installer or update transaction. | Add versioned installation records, legacy reading, managed slots, provenance, selection/last-good metadata, removal, and reconciliation. |
| `.../context_assistance_service*.rs` | Bounded native status, activation/recheck jobs, runtime generation, lifecycle cleanup; status labels qualification as `local_candidate`. | Own installation/update jobs, transactional switching, actual qualification, and recovery without starting SDK work from status requests. |
| `dashboard/src/context-assistance/history-api.ts` | History parser/type require SDK version `0.14.1`. Native history already accepts an SDK-version string. | Preserve provenance and read known historical schemas across versions; do not replace one literal with the next literal. |
| `dashboard/src/context-assistance/{types,status,settings-controls,workspace-model}.ts*` | Runtime display can show dynamic SDK version; installation and qualification contracts remain candidate-specific. | Add installed/release/update models, compatibility reasons, progress, pinning, and rollback controls. |
| `src/codex_plugin_scanner/guard/{native_context_assistance.py,daemon/context_assistance_http.py,cli/context_assistance_commands.py}` | Thin native control transport and CLI; help contains the current fixed release. | Extend bounded native operations and rendering; keep installation and compatibility decisions in Rust. |
| Native release/pack helpers and `rust/Cargo.toml` | Existing bounded release transport decisions, archive handling, hashing/crypto, locking, and `pep440_rs`. Some existing release transport byte movement remains Python-owned. | Assess reusable primitives and their limits. Keep new CIGAR lifecycle/verification logic native; do not assume extension-pack formats, trust roles, host lists, or size limits fit Python wheels. |

The native saved-note `version` fields describe note revisions, not SDK releases. Do not mechanically rename or migrate every field named `version`.

## Architecture decisions to carry into the goal

### Release catalog and compatibility

Use one schema-validated, declarative catalog with exact release entries and a bundled bootstrap snapshot. Allow an explicit check for newer authenticated catalog data and an authenticated offline import. Cache verified data so installed releases remain manageable offline. A public package index is discovery evidence; it is not execution approval.

Each entry must describe SDK version, native core version, worker protocol, adapter/profile ID and revision, minimum Guard contract/build support, final CPython 3.14 requirements, platform/ABI tags, feature requirements, storage compatibility, release channel, artifact/dependency locks and hashes, provenance, and qualification receipts. Record signature/trust-root identity, catalog revision, expiry, and withdrawal status at the catalog level as appropriate. Use PEP 440 ordering for Python releases, including prereleases and local candidates; avoid lexical comparisons and assumptions that SDK/core versions always match.

Profiles express what a shipped adapter can handle. A release still needs exact artifact approval and platform qualification before activation. Matching a broad version range or worker protocol alone is insufficient. Keep discovery, compatible, qualified, installed, verified, selected, active, last-good, pinned, and withdrawn states distinct.

Trust must come from Guard-authorized catalog keys or a deliberately scoped existing trust role. Do not infer trust from a URL, TLS alone, self-reported manifest hashes, or an arbitrary key supplied with an archive. Design key rotation, replay protection, expiry, withdrawal, and cached/offline behavior. Production key custody and catalog publication remain outside local implementation unless separately authorized. Test keys must never become production trust roots.

### Managed installations and adapters

Own immutable environments under Guard's private context-assistance storage. A slot identity binds SDK release, core/worker, platform, interpreter fingerprint, adapter, dependency lock, and artifact fingerprints. Separate SDK bytes from writable workspace, job, and evidence storage. Never upgrade the active environment in place or alter system Python or Guard's host environment.

Use a previously verified interpreter and a qualified venv/wheel installer flow. Fetch locked wheel/dependency bytes through bounded native-controlled acquisition, then install offline with no source builds or unbounded dependency resolution. Establish how installer bootstrap is verified and packaged on a machine with Python 3.14 but without usable pip/ensurepip. Do not add an ambient `uv` or host-pip dependency by accident. Existing advanced local enrollment remains available with explicit candidate provenance.

Preserve the actual final CPython `(3, 14)` gate, platform/ABI qualification, and existing rejection of unsupported implementations/builds. Patch releases such as 3.14.7 are allowed when qualified. A future SDK requiring 3.15 remains incompatible under the user's current requirement. Python discovery/probing is an explicit setup action; passive UI/status refresh must not execute interpreters. The browser chooses opaque discovered/verified IDs rather than submitting arbitrary executable paths or hashes.

Keep a stable Rust graph/broker contract. For a compatible release, select a shipped, qualified adapter using catalog data. For a breaking release, add a narrow adapter and qualify it before enabling the release. Because the bridge uses isolated `-I -S` Python, split adapters cannot rely on modules in Guard's host installation or arbitrary SDK/plugin paths. No downloaded executable adapters, runtime `eval`, or untrusted module selection.

### Installation, switching, and data

An explicit install operation may download and run bounded synthetic verification without enabling CIGAR or granting source/app access. Installing, selecting, and starting are separate actions. Default to manual updates and a pinned selection; offer optional update notifications and preview-channel opt-in. Installing a version does not automatically switch an active user.

Stage and verify the replacement while the selected installation remains intact. Serialize conflicting lifecycle operations. Use a durable switch journal and atomic selection update to coordinate runtime generation, settings, last-good metadata, and data compatibility. Only interrupt the old runtime at the commit boundary. Bound the interruption and cancel/drain optional context work according to the existing execution contract.

Changing CIGAR selection must not invalidate a Guard execution approval. CIGAR runtime leases and scoped source/app grants need a fresh authority generation after a switch or rollback. Do not revive grants, pairing secrets, execution handoffs, or SDK authority from backups. Explain re-pairing and source reauthorization when required, and preserve preference values without treating them as active authority.

Separate persistent evidence from live authority. Version readers/writers by their actual schema and producer, preserve old history labels, and classify each new release's storage compatibility. Back up or clone supported private evidence before a migration; validate the migrated copy before committing. Restore a compatible prior evidence generation on rollback. If neither a reversible migration nor a supported read path exists, block the switch with an explicit recovery choice. Never quietly delete saved context or migrate Guard's approval store as part of an SDK upgrade.

After a known activation failure, restore the last-good selection/data and its previous requested on/off intent. Only restart it if the explicit switch action authorized that behavior and policy still permits it. Never silently select another release. After cancellation, lost replies, or a crash with uncertain effects, reconcile the durable job/selection records before offering retry. Keep Guard operational even when optional CIGAR work fails.

### User controls

Extend the existing CIGAR workspace with **Versions & updates**, retaining the current clear Start CIGAR action and tutorial navigation. Show current SDK and Python versions, platform, channel, qualification, selected/active/last-good state, and the reason a release cannot be used.

Provide Check for updates, Install version, Verify, Select, an explicitly described Switch and start action when appropriate, Pin, Roll back, and Remove unused version. Show what will stop/restart, any feature or data changes, and any reauthorization needed before a switch. Hide no required step behind “preference saved.” Distinguish learning progress from actual installation/readiness.

Keep UI choices focused: manual updates by default; optional notifications; stable versus preview; selected version and retention of rollback versions. Reuse existing feature, data, and policy controls. Do not duplicate controls for app sharing, persistence, or execution in the updater. Unknown/unqualified releases show why they are unavailable and whether a Guard update is required.

## Ordered execution work packages

Execute these phases in order. The sizes are relative complexity, not time estimates. The critical path is artifact/profile design, immutable installation, data compatibility, and crash-safe switching. UI work depends on settled native contracts.

| Phase | Size | Required result before moving on |
| --- | --- | --- |
| P0 | M | Baseline, exact release sources, proposed target, qualification scope, and prerequisite ledger. |
| P1 | L | Version/catalog/profile, trust, API, job, switch, and storage contracts with explicit failure semantics. |
| P2 | L | Version-aware artifact/runtime verification and packaged adapter selection, preserving 0.14.1 behavior. |
| P3 | M | Versioned registry/settings/history migration with legacy installations preserved. |
| P4 | XL | Verified acquisition, interpreter/setup flow, immutable installation, and durable bounded jobs. |
| P5 | L | Storage compatibility checks and reversible evidence preparation. |
| P6 | XL | Atomic switch, last-good rollback, crash recovery, and lifecycle concurrency handling. |
| P7 | M | Operator API/CLI and policy controls, including authenticated catalog refresh/import. |
| P8 | L | Versions & updates UI, actionable progress/recovery, and upgrade walkthroughs. |
| P9 | XL | Real release qualification, upgrade/rollback, failure injection, and approval isolation evidence. |
| P10 | L | Installed/frozen acceptance, performance checks, maintainers' bump workflow, and final receipts. |

### P0 — Establish the exact baseline and target

1. Read `~/.hol-support/SAFETY.md`, repository instructions, [approval-invariant.md](../approval-invariant.md), and the native ownership/integration documentation. Inspect Git before changing files. Record HEAD and the existing dirty-tree inventory without staging or discarding it.
2. Capture the current release pins, registry/config schemas, bridge methods/capability checks, existing job semantics, installed/frozen build paths, and local Python/platform facts. Use existing evidence rather than repeating broad test suites before a code change.
3. Recheck official package metadata and release provenance. Select baseline A (`0.14.1` candidate) and a real approved newer B, including wheel/dependency locks, source revision, worker identities, release signatures if applicable, and the platform to qualify. Do not modify the SDK checkout.
4. Record external prerequisites: availability of B, authorized catalog trust roots/hosting for a production remote feed, and additional platform infrastructure. Continue independent implementation if B is unavailable, but keep real upgrade qualification explicitly pending.

Exit: a baseline/target matrix and acceptance plan with facts separated from proposals. Do not substitute public 0.14.0 for newer B.

### P1 — Freeze the compatibility and lifecycle contracts

1. Define catalog, exact-release identity, platform artifact lock, compatibility profile, and qualification-receipt schemas. Generate or share derived types/fixtures so consumers do not maintain release lists independently.
2. Define trusted bundled, refreshed, cached, and offline-imported catalog behavior. Specify signature scope, key rotation/revocation, revision/replay rules, size/time bounds, yanked releases, offline operation, and actionable error codes. Reuse existing native primitives only after checking their scope.
3. Define installation schema v2, selection/last-good/pin settings, adapter resource identity, and backward-read policy for existing v1 local candidates. Separate the Guard product version/native contract from Cargo package versions.
4. Define native job and operator API contracts for catalog checks, discovery, install, verify, select/switch, rollback, cancel, remove, and recovery. Include idempotency keys, request/response bounds, generation/conflict handling, lock ownership, terminal states, and restart reconciliation.
5. Write the switch/storage decision matrix before implementing it: off versus active, memory versus persisted evidence, requested feature proofs, unsupported capabilities, migration direction, failures before/after commit, and in-flight execution handoffs. Reject unsupported transitions rather than silently downgrading features.

Exit: contract fixtures cover valid/invalid versions, installation states, and each transition. Unresolved trust or data assumptions have named gates rather than permissive fallbacks.

### P2 — Modularize the SDK boundary and remove distributed pins

1. Replace the single SDK-version assumption with an approved release/profile passed into artifact inspection and verified launch. Validate SDK, core, protocol, platform, hashes, and profile independently; keep validation before execution and after import/handshake.
2. Make runtime/status identities owned dynamic values derived from verified artifacts, including producer version, adapter/profile revision, and proven capabilities. Keep a bounded metadata-only status path.
3. Package a Guard-owned adapter for the current SDK behind the normalized graph/broker contract. Add an explicit adapter interface for doctor, compilation, sharing/broker, persistence, and execution-context proof. Avoid duplicating the whole host engine for each release.
4. Remove active-version literals from CLI/help and client validators where they are actually release constraints. Keep historical fixtures explicitly labeled with the release they test. Unknown SDK/profile pairs must still fail before activation.

Exit: current 0.14.1 behavior remains verifiable with unchanged protection checks; an unsupported release cannot start by merely changing metadata. Compatible release selection is data-driven through a shipped profile.

### P3 — Evolve installations, settings, and history safely

1. Add immutable installation records carrying complete version, interpreter, dependency/artifact, adapter, provenance, and qualification identity. List CIGAR versions directly rather than making users infer them from opaque runtime IDs.
2. Read existing candidate records without silently approving them as public stable releases. Use protected atomic writes for explicit migration, retain IDs/references where possible, and reject malformed/ambiguous records. Reverification remains necessary for readiness.
3. Persist selection, pin, last-good, retention, and update preferences without changing the CIGAR enabled preference. Respect effective policy and settings revision checks.
4. Update native/Python/TypeScript contracts together. Keep known historical evidence readable with its original producer/schema; reject unknown payload structures without assuming all SDK version strings are unsafe. Inventory saved evidence separately from native memory history.
5. Define installation limits, retained last-good protection, disk budgets, orphan detection, and removal rules. Never remove active, selected, in-use, or protected last-good bytes; never delete external operator-owned Python environments.

Exit: legacy candidate enrollment and new managed slots coexist; history remains correctly labeled; passive installation listing does not import CIGAR or execute Python.

### P4 — Implement acquisition, immutable environments, and jobs

1. Add explicit bounded interpreter discovery/probe using native-owned facts and opaque IDs. Preserve exact final CPython 3.14/platform/ABI requirements, including a regression for the user's valid 3.14.7 runtime. Explain missing installer components separately from Python incompatibility.
2. Resolve a selected catalog entry to an exact wheel/dependency set. Verify trusted metadata and download to a private staging area using allowed origins, bounded redirects/bytes/time, redacted errors, and digest/provenance checks. Support an authenticated offline artifact bundle through the same verifier.
3. Create a fresh versioned environment with the verified installer flow. Install only exact locked wheels offline; reject source distributions, unreviewed build steps, ambient configuration, direct URL dependencies, and fallback to the system environment. Recheck the finished package/worker tree.
4. Run bounded doctor and synthetic compile plus requested sharing, persistence, and execution proofs appropriate to the profile. Tests use synthetic data, not the user's workspace. Publish an installation record only when the required checks pass.
5. Implement native background jobs with progress, cancellation, deadlines, disk/space checks, cleanup, and a durable result. Extend/reuse current activation jobs without blocking status or hooks. Distinguish safe retries from unknown outcomes and make repeated requests converge on one installation/job.

Exit: an explicit install can create a verified, inactive slot while the current runtime and enabled preference remain unchanged. Failed/cancelled installs leave no selected partial environment or leaked worker. Missing bootstrap components have a clear supported recovery path.

### P5 — Prepare data compatibility and reversible migrations

1. Inventory SDK/broker SQLite data, Guard-owned saved evidence, history, notes, and ephemeral graphs separately. Specify producer/schema compatibility per profile rather than assuming all data belongs to the SDK.
2. Implement a preflight returning readable/migratable/incompatible/unknown, required disk space, backup scope, and feature changes. Keep live grants and execution authority outside evidence migration.
3. For supported changes, prepare a validated copy or transactionally versioned evidence generation, with durable ownership and rollback metadata. Preserve retention/delete preferences; avoid an extra permanent copy of sensitive evidence without a cleanup policy.
4. Implement forward/backward compatibility checks and recovery for corrupt, missing, interrupted, or newer-schema data. Refuse destructive or irreversible transitions unless a separate explicit supported data choice exists. Never invent a migrator for an undocumented SDK format.

Exit: switching has a tested compatible data plan or a clear refusal. The prior installation has a compatible recoverable evidence generation; restores cannot restore runtime authority.

### P6 — Implement transactional switch and rollback

1. Serialize install finalization, selection, activation, stop, settings changes, removal, and rollback where they conflict. Use expected generation/settings revisions so another client cannot switch a stale selection.
2. Prepare replacement identity, required feature proofs, data generation, and a durable transaction journal before changing the selected runtime. Keep the old environment and its recoverable data intact.
3. At commit, drain/cancel optional jobs under bounded rules, settle or invalidate in-flight CIGAR handoffs, close the old actor, change the selected installation/data generation atomically, and activate only according to the user's explicit action and effective policy.
4. Health-check the replacement and commit last-good only after required proofs succeed. On a known failure, restore the previous compatible selection/data and requested intent. On uncertain failure, show recovery required and reconcile before retry; do not run two competing workers.
5. On daemon restart, reconcile every durable transaction boundary. Rotate the CIGAR authority generation and require fresh grants/pairings where required. Preserve Guard approvals and offer both supported approval choices throughout CIGAR lifecycle changes.
6. Add an explicit rollback operation using the same transaction engine. Protect retained last-good files from cleanup and require explicit confirmation of any feature/data differences through the normal operation contract.

Exit: A-to-B and B-to-A use one tested transaction path; no half-selected slot survives a crash. Optional context failure cannot stall Guard command evaluation or revoke a saved Guard approval.

### P7 — Expose the operator workflow and policies

1. Extend the existing native control transport and operator-authenticated HTTP routes with bounded version/job/catalog operations. Browser requests name approved releases/opaque IDs; they do not supply executable paths, package indexes, approval fingerprints, or authority-bearing keys.
2. Add thin CLI verbs under `hol-guard context` for versions/check, install, verify, switch, rollback, pin, jobs/cancel/recover, and remove. Finalize exact names in P1 and keep JSON/human outputs aligned with the same native result.
3. Wire manual/pin/channel/notification/retention settings through existing effective-policy controls and locked settings. No automatic switch, downgrade, opt-in, feature enablement, or source scan as a consequence of catalog refresh.
4. Keep MCP/source-consumer capabilities separate from runtime administration. Ordinary paired AI connections cannot install packages, approve candidates, change catalog trust, or broaden permissions. Continue supporting explicit local operator enrollment without exposing it as arbitrary browser input.

Exit: CLI and HTTP produce the same lifecycle results and policy restrictions. Production remote feed configuration is usable only with an authorized trust root; otherwise show its exact unavailable state while preserving bundled/offline operation.

### P8 — Build the Versions & updates experience

1. Add a prominent Versions & updates area in the CIGAR workspace. Show selected/active SDK, Python, platform, channel, provenance/qualification, installed versions, last-good, pins, compatible releases, and concrete incompatibility reasons.
2. Implement explicit install-only and verify/select/switch actions. Explain a running runtime's interruption, required feature changes, saved-data handling, and re-pairing before committing. Keep the existing Start CIGAR action accurate when installation is complete but the runtime is off/not started.
3. Render bounded job progress, cancellation, terminal failure, unknown-outcome recovery, rollback, and safe removal. Do not equate saved preference, downloaded artifact, or tutorial completion with a verified active runtime.
4. Add walkthroughs for first installation, upgrading while pinned, switching an active runtime, and restoring the last working version. Explain Context Intelligence Graph Agentic Runtime and the difference between CIGAR releases, the selected Python, and a Guard adapter update.
5. Validate keyboard/screen-reader use and narrow/wide layouts using the existing UI framework. Preserve the current tutorial route/session behavior and source/app/data control flows.

Exit: a new user can install a supported release and start it without shell enrollment; an existing user can see exactly which version will run, upgrade intentionally, and roll back from the UI.

### P9 — Qualify real releases and failure behavior

1. Qualify exact A and genuinely newer B artifacts on the first supported platform with all requested feature proofs. Demonstrate real A-to-B-to-A behavior through UI/CLI/native installed paths and record hashes, versions, commands, results, and worker cleanup. Reinstalling A or editing its version label is not an upgrade test.
2. Test wrong Python minor/implementation/build, valid final 3.14 patch releases, wrong platform/ABI, package/core/worker/protocol mismatch, unsupported adapters/capabilities, malformed legacy records, and historical-schema parsing.
3. Inject download interruption, invalid/replayed/expired catalog, revoked/yanked artifacts, tampering, dependency mismatch, no network, missing installer, disk exhaustion, cancellation, lost replies, process death, settings conflicts, concurrent switches, and interrupted cleanup. Exercise each durable switch boundary and prove bounded recovery/no orphan descendants.
4. Exercise memory and supported persisted-evidence paths, forward migration, rollback after a data write, corrupt/incompatible schemas, old history, retention, and fresh authority after a switch. If a migration is unsupported, verify the user sees a refusal before old data/runtime is disturbed.
5. Verify off stays off, install-only stays inactive, pin/manual settings hold, policy restrictions hold, optional feature changes are explicit, status never probes, and existing Guard Allow once/Always allow approvals survive upgrade and rollback.

Exit: actual release/platform evidence and failure-test evidence are separate from synthetic compatibility fixtures. If approved newer B is unavailable, leave real upgrade qualification pending and do not mark the complete upgrade objective achieved.

### P10 — Package, measure, and prove the next bump is modular

1. Run change-appropriate native, transport/CLI, client-contract, UI, and browser suites. Compare with baseline failures; the current known non-context TypeScript diagnostics and absent Bun in the existing test environment must not be mislabeled as new regressions or successful checks.
2. Build/test installed-wheel and frozen/onefile Guard variants with adapters, catalog snapshot, installer resources, and upgrade migrations included. Test a separate Python 3.14 environment when Guard uses an older supported host Python. Qualify other platforms only with real artifacts/runs.
3. Check off/status/hook-path behavior and upgrade-time contention against existing native performance acceptance. Keep SDK imports/downloads/workspace scans out of synchronous hooks. Demonstrate bounded worker/process cleanup after success, cancellation, rollback, and owner loss.
4. Add a deterministic catalog-entry/qualification generator and CI validation. Produce a maintainers' runbook: select upstream release, lock all artifacts/dependencies, verify provenance, run per-profile/platform/feature qualification, update the catalog and receipts, sign/publish through an authorized release process, and test refreshed/offline catalog consumption.
5. Prove a third compatible release entry can flow through the existing adapter with catalog/lock/receipt changes only. A synthetic fixture can prove this mechanism, but must be labeled synthetic; release qualification requires real artifacts. Document exactly when a new adapter or Guard binary is required.
6. Record final implementation scope, release/platform matrix, test/performance results, rollback limitations, catalog trust/hosting status, and next actions. Preserve historical original-goal evidence and current UI work. Prepare publication artifacts locally; do not push, publish, change live hooks, or upgrade the user's preview without separate authorization.

Exit: repeatable release addition, installed/frozen acceptance, and final evidence support the exact feature/release/platform claims made to users.

## Acceptance checklist for the future goal

- [ ] One authoritative release catalog/profile mechanism replaces distributed active SDK pins without weakening exact artifact checks.
- [ ] Users can obtain compatible catalog data independently of a Guard binary update, through an authorized remote feed or authenticated offline import. Remote production deployment status is explicit.
- [ ] Compatible releases reuse shipped adapters; incompatible releases show a clear Guard-update/adapter requirement.
- [ ] A verified final CPython 3.14 runtime, including the user's qualified 3.14.7, is detected accurately. Other Python minors or unsupported implementations/builds remain unavailable.
- [ ] Explicit installation creates isolated immutable bytes with exact locked wheel dependencies and preserves the active/selected runtime until a deliberate switch.
- [ ] Manual selection, pinning, update preferences, installed versions, last-good rollback, cleanup, cancellation, and job recovery work through native operator contracts and the UI.
- [ ] Real approved A-to-newer-B-to-A tests pass on every claimed platform; actual release claims are not inferred from fixtures or upstream platform inventories.
- [ ] Supported saved evidence survives upgrade/rollback with correct version labels; unsupported migrations refuse safely; previous authority never returns from backups.
- [ ] CIGAR remains optional and policy-controlled. Setup/install does not silently enable it or grant source/app/sharing/execution access.
- [ ] Guard evaluation and Allow once/Always allow behavior remain correct through each lifecycle state and failure.
- [ ] Installed/frozen packaging, UI/tutorial regressions, change-appropriate tests, process cleanup, and relevant performance checks have recorded results.
- [ ] The next compatible-release bump is demonstrated as catalog/lock/qualification work, with a documented adapter-change path for breaking releases.

## Goal text ready for a later creation step

Use the following objective only after execution is requested, with GPT-6.1 Sol and reasoning `max` selected in the execution session:

> Implement user-controlled, modular CIGAR upgrades in `hol-guard-cigar-integration` on the existing feature branch by executing P0 through P10 in `docs/guard/cigar-integration/CIGAR_UPGRADE_PLAN.md` in order. Preserve the existing uncommitted UI/tutorial work and original integration acceptance. Build a declarative authenticated release/compatibility catalog, shipped versioned SDK adapters, backward-compatible installation/history contracts, immutable isolated final-CPython-3.14 installations, bounded native jobs, reversible data handling, atomic switching/last-good rollback and recovery, thin operator CLI/HTTP controls, and a Versions & updates UI with walkthroughs. Demonstrate real approved 0.14.1-to-newer-release-to-0.14.1 upgrade/rollback and installed/frozen qualification for every claimed platform, plus unchanged Guard approvals, optional/off behavior, and relevant performance. Make later compatible releases addable through catalog, exact locks, and qualification receipts without application-code edits; require a qualified adapter/Guard update for breaking contracts. Follow the plan's invariants, phase gates, and acceptance checklist. Record unavailable release/trust/hosting prerequisites honestly, continue independent work, and do not declare the full objective complete while required real qualification is outstanding. Prepare any release artifacts locally without publishing, changing live hooks/system Python, modifying CIGAR SDK sources, or updating the user's preview as a side effect.

During execution, maintain a separate `CIGAR_UPGRADE_EXECUTION_LOG.md` containing each phase's decisions, exact files changed, checks/results, artifact identities, remaining gates, and the next ordered step. Execution is authorized; keep that log current and preserve original integration acceptance separately.
