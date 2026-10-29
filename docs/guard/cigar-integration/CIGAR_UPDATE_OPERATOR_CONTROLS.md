# Operator controls for CIGAR updates

Installation and live-switch jobs now share a bounded native API, CLI verbs and authenticated HTTP framing. Preparation keeps the current actor serving. Commit requires the exact native generation and an explicit reconnect acknowledgement. Installation remains separate from selection and activation, and disabled users stay disabled.

The resident advertises context-assistance-versions-v1. Strict kind=versions requests return guard-cigar-versions-result.v1 with native result metadata; CLI/HTTP include current native state. Nonzero canonical decimal generation strings preserve values beyond JavaScript's exact-integer range. Unknown fields, executable paths, caller-supplied hashes, rollback targets and grant facts are rejected.

## Native actions

| Action | Fields after action | Effect |
| --- | --- | --- |
| releases | none | Read the authenticated bundled or imported catalog; no refresh or execution. |
| catalog | none | Inspect authenticated source/checkpoint, freshness, public-key IDs and withdrawals; no probe. |
| import_catalog | signed_catalog | Verify and retain a separately authorized signed catalog; no install/selection/activation. |
| refresh_catalog | job_id | Check the separately configured feed in a bounded cancellable native job; publish authenticated metadata only. |
| interpreters | none | Read verified interpreter metadata without probing. |
| jobs | none | List setup/install/reverify/switch/rollback progress, at most 32 combined jobs. |
| job | job_id | Inspect progress without creating runtime authority. |
| setup_interpreter | job_id, build_id | Prepare approved private CPython without enabling CIGAR. |
| install | job_id, build_id, interpreter_id | Install or reverify exact approved bytes in the existing background worker. |
| prepare_switch | job_id, target_runtime_id, expected_generation | Prepare an installed replacement beside the active source. |
| prepare_rollback | job_id, expected_generation | Prepare authenticated last-good using current reviewed data. |
| commit | job_id, expected_generation, reconnect | Commit a live Ready owner only with reconnect=true. |
| cancel | job_id | Cancel work while retaining ownership until cleanup acknowledges. |
| recover | job_id, expected_generation for switch jobs | Explicitly reconcile supported recovery/completion without starting an SDK or restoring grants from progress. Omit the generation for preparation jobs. |

Switching currently requires an active source. [Offline authenticated catalog import](CIGAR_AUTHENTICATED_CATALOGS.md) is now implemented. [Bounded remote refresh](CIGAR_CATALOG_REFRESH.md) is now implemented locally with separate feed/root configuration. Off-state selection, pins/update/retention policy, safe removal and production feed/trust qualification remain unfinished P7 work. Missing data or feature proof retains the existing native refusal; no implicit erasure, feature downgrade or enablement choice is added.

## CLI and HTTP

Root hol-guard context and nested guard context commands provide versions, catalog, catalog-import, catalog-refresh, interpreters, jobs, job, setup-python, install, switch, rollback, commit, cancel and recover. switch/rollback prepare only; commit is separate and requires --acknowledge-reconnect. Copy --generation exactly from context status for switch/rollback/commit and switch recovery. Choose opaque IDs from native metadata, never executable paths or package indexes. The existing check command still verifies the saved runtime. JSON returns the native result/state envelope; human output reports phases and recovery without inferring activation.

GET /v1/context-assistance/versions, /catalog, /jobs and /interpreters derive fixed read actions; a body cannot request a mutation. POST /v1/context-assistance/versions accepts an input action. Existing dashboard/header operator authorization is required, protection-repair sessions cannot use these paths, and mutation framing uses the existing settings approval gate. Proof fields stay outside the CIGAR request. Cancellation and metadata need no new expansion approval. Paired source/agent routes gain no administration capability.

Version requests enter the resident's existing optional-work lane, bounded to two requests including response delivery. Saturation returns a request-bound busy result while health and Stop remain available. Native workers retain verification, disk I/O, deadlines, cancellation, journals, data transfer and cleanup. Guard's shared health circuit and hook-worker pool are unchanged.

## Validation and scope

Python: 67 pass, including 31 new CLI/transport/HTTP cases. Native Service: 17 pass/11 SDK gated. Daemon authorization: 10 pass. Optional-work lane: 15 pass, including blocked version replies while health/Stop stay available. Rust 1.88 compilation, Rust/Python formatting, Ruff and authority/I/O/privacy gates pass. Native Clippy retains 36 errors in 23 hash-verified unchanged baseline files, with zero new errors. Production Rust 1.88 warnings fall from 60 unconnected entries to two unused helpers.

A separately executed actual SDK case uses bound native request-evaluator envelopes. Ready cancellation preserves the source and settings; stale/unacknowledged commits refuse; forward switch preserves complete notes and original expiry. After clearing the old review and admitting a new review, rollback keeps the latest vector without resurrecting the removed review. Lost-reply retry returns the same job. Stop and off-state job inspection preserve opt-out. No matching CIGAR bridge/broker/switch process remained afterward.

This is local macOS ARM64 final 0.14.1, external Python 3.14.7/3.14.10 and a test-qualified target. It does not qualify b47380, a newer SDK, managed interpreter end-to-end, installed/frozen sockets, CLI/HTTP end-to-end with the SDK, or other platforms. SDK/daemon-route checks preceded the final optional-work routing change; their image identities remain separate from the final Service/lane image. The later change has its own lane/compile/Service evidence. Earlier zero-test filtering, pytest socket denial, Ruff diagnostics and formatter PATH failure remain non-acceptance results.

[Evidence](evidence/upgrades-operator-controls-20261028.json) binds sources, images, logs and preservation. Remaining P6 recovery/data-choice matrix, P7 policy/production feed qualification/off-state selection/removal, P8 UI and P9/P10 approved newer-release, installed/frozen/platform, approval/load/performance and maintainers' bump qualification are still required. The full P0–P10 goal remains active and incomplete. Existing workspace/tutorial work, original acceptance/log, live profiles/hooks/preview, upstream SDK source, system Python and Guard execution approvals are preserved.

Preference reads use action preferences through the existing authenticated versions transport. set_preferences carries the exact read revision and a strict whole preference table; it retains the settings approval gate. Pin/unpin/update-policy CLI writes retain other requested fields and pass the user revision unchanged. See [the preference contract](CIGAR_UPDATE_PREFERENCES.md) for pin scope, unsupported automatic/retention controls, current-runtime/off-state distinctions and the final SDK evidence.

The [cold data checkpoint](CIGAR_COLD_DATA_PREPARATION.md) proves closed-store export, deferred carry/admission and a disabled SDK/data transaction through native primitives. It does not yet add a public cold-selection action: prepare_switch still requires the active source. A bounded cancellable off-state job, initial/unavailable-source/data-choice flows and appropriate routing of all supported selection changes remain required before operator/UI acceptance.

The [disabled operator checkpoint](CIGAR_OFF_STATE_SELECTION.md) now supports prepare_switch/prepare_rollback for an off profile with a selected readable source installation. Job results report keeps_disabled=true/reconnect_required=false, and commit accepts reconnect=false for that native path. CLI commit may omit --acknowledge-reconnect; a live switch still requires it in native code. HTTP authentication/settings-write approval is unchanged. Resident envelope tests cover cancellation, off commit, acknowledgement repair, missing target, off rollback and fresh grants. Initial/unavailable-source/data-choice workflows, full crash recovery, normal settings routing and actual CLI/HTTP process qualification remain required.

An [ordinary settings replacement](CIGAR_SETTINGS_SELECTION_GUARD.md) now returns native_context_assistance_switch_required plus an actionable validation message. Use the existing prepare/commit controls for a different selected installation; direct settings replacement cannot interrupt a verified running source or rewrite the disabled selection. Same-ID edits/enablement retain their existing contract. Initial/reset/clearing/data-choice flows still need complete routing and qualification.

For a disabled profile with no selected runtime or saved data, prepare_switch followed by explicit commit now performs [initial selection](CIGAR_INITIAL_SELECTION.md). Progress reports operation=select, initial_selection=true, keeps_disabled=true and reconnect_required=false. Enable/activation and fresh file/note grants remain separate. There is no last-good rollback before a real prior selection. Existing-data choices and full ordinary-settings/reset routing remain incomplete.

For an interrupted initial commit with its exact target already selected, recover(job_id, expected_generation) now queues [bounded private target re-verification](CIGAR_INITIAL_RECOVERY.md). Poll the same job; operation=recover exposes its attempt and fixed deadline. A live retry reuses the worker; cancellation keeps the target off, and a new explicit recover gets a fresh attempt. Healthy acknowledgement remains metadata-only. This does not implement all selected-source/data-choice recovery.

## Dashboard Versions & updates checkpoint

The workspace now exposes explicit preparation, acknowledged selection/rollback, cancellation/recovery, signed catalog controls and CAS update preferences through these same native actions. Opening the tab reads metadata only. See [the UI contract](CIGAR_VERSIONS_UI.md) for eleven fixture-browser checks and remaining notification, routing and installed SDK qualification limits.

## Committed disabled recovery follow-up

[Committed disabled-selection recovery](CIGAR_DISABLED_RECOVERY.md) extends the bounded verifier to already committed disabled selections and rollback with a previous SDK/data pair. It requires exact post-commit settings and preserved original intent, closes the temporary SDK before metadata completion, keeps CIGAR off and supports explicit cancel/retry. Later Stop/settings edits, live committed transitions and other durable phases retain their safe refusal and remain pending.

## Later Stop and current preferences

[Stop-aware committed recovery](CIGAR_STOP_RECOVERY.md) now re-verifies Committed/Healthy targets against current disabled settings, including previously live switches after Stop, without restoring activation. Original job mode/request hashes remain bound; current settings/selection/data changes after admission invalidate the attempt. CommitIntent with later settings, still-enabled committed targets and other durable phases remain outside this checkpoint.
