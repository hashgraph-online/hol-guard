# Selection and rollback while CIGAR is off

The existing native `prepare_switch`, `prepare_rollback`, job, cancel, commit and recover controls now support a disabled profile that has a selected, readable installation. Preparation leaves the saved runtime ID and enablement unchanged. Explicit commit selects a coupled SDK/data pair while keeping CIGAR off. A later, separate enable/activation and fresh app/source grants are required to use it.

Initial selection with no source installation, unavailable/withdrawn source data choices, and recovery from every interrupted preparation/commit phase remain separate required work. This checkpoint must not be read as acceptance of those flows.

## One lifecycle owner

Both serving and disabled selection use the same profile lifecycle lease, shared 32-job namespace, exact request and native generation checks, durable progress, cancellation markers and 120-second worker budget. The selected runtime must be different from the target. Disabled capture requires both requested and effective enablement to be false, no serving actor or pending verification, and acknowledgement that any retiring actor has closed. Policy restrictions and malformed settings still refuse.

Preparation runs in the native background worker. Temporary source/target SDK checks use separate cancellation tokens forwarded from the job. Closing one private SDK cannot cancel the job or the other SDK. Every private runtime closes before the job releases its lease. These explicitly requested maintenance processes are not attached to the serving Service; passive status, history and catalog reads still start no SDK process.

The source SDK proves reviewed data from the authenticated native scope index through the [cold export contract](CIGAR_COLD_DATA_PREPARATION.md). No project files, old app views, clients, grants or execution approvals are reconstructed. The source inventory is captured after source SDK closure because SQLite may checkpoint during that closure. For an existing generation, the selected producer and Ready state must match. A new generation carries deferred data with original provenance and expiry.

## Ready and commit

Job results expose `keeps_disabled=true` and `reconnect_required=false`. Existing live jobs retain their reconnect requirement. The disabled mode participates in job identity and cannot change on an existing job. Legacy records omit the new default-false field and retain their original request fingerprint.

Ready remains tied to the live coordinator and its exact native state. The prepared source cache inventory and complete authenticated source/target generation digests are checked again at commit. The target installation is remeasured and its transport/artifacts checked before its private process closes. Commit then uses the short native state/settings lane and the existing byte-CAS, sealed journal and coupled selection owner. It changes only the selected runtime ID, advances the native generation and keeps both enablement values false. No serving actor, scope or permission is published.

The operator supplies `reconnect=false` for this path. The CLI accepts commit without `--acknowledge-reconnect` and explains that CIGAR stays off. A running-runtime commit still requires that explicit acknowledgement in native code; the CLI cannot infer or waive it. HTTP commit keeps its existing operator authentication and settings-write approval gate for both forms.

Cancel retains cleanup ownership until private SDKs and unselected preparation are gone. Failure before a new transaction does not cancel an earlier completed transaction or discard its data. Repeating a completed request repairs/returns metadata rather than switching again. An explicit Stop or settings change invalidates the captured native generation/raw settings and cannot become an implicit enable.

## Rollback and acknowledgement recovery

Disabled rollback resolves the authenticated exact last-good installation and prepares current deferred data for it. It does not select an old data snapshot or restore old grants. The operator commits separately, while still off. Later activation verifies the selected SDK/data pair again; fresh source and note-read permissions govern admission.

A missing final completion acknowledgement can be reconciled from a sealed Healthy disabled transaction, exact current settings bytes, matching current selection and an authenticated Ready data generation. Recovery checks the caller's current native generation and requires the Service to remain off without an actor or competing job. It updates completion/last-good metadata without starting an SDK, reconstructing authority or replaying the switch. Earlier incomplete or ambiguous phases continue to refuse for explicit recovery; their complete bounded recovery matrix is not claimed here.

## Verification scope

The published-SDK operator case uses final 0.14.1, external CPython 3.14.7/3.14.10, a test-only signed catalog and test-only target qualification on local macOS ARM64. Through resident operator envelopes it prepares/cancels a Ready job, commits without reconnect while off, injects a final metadata-write failure, reconciles without activation/replay, refuses a missing target without damaging the prior transaction, and rolls back while still off. A separate explicit enable and fresh Codex/dashboard grants restore the original reviewed digests and expiry. This is resident operator acceptance, not actual CLI/HTTP process or managed-Python end-to-end qualification.

The initial SDK run reached rollback but then a reused test activation helper wrote the forward target ID. Production refused the mismatched selection. The helper now enables only the current selected preferences; production checks were unchanged. The first Rust 1.88 compile found two missing clock-error conversions, and the first Python lint found two long presentation lines. Those failures remain separate from final acceptance.

The established actual live-context/catalog-refresh/reverification/switch/latest-data rollback case is retained as a distinct companion check. Unit regressions cover backwards-readable job identity, cancellation isolation, disabled capture/Stop fences, strict operator inputs and authenticated generation digest changes. Python tests cover both CLI commit forms, truthful Ready output and unchanged HTTP authorization for both forms. Counts overlap and must not be summed across suites or images.

The [evidence receipt](evidence/upgrades-off-state-selection-20261028.json) records final source/image/input hashes, results, failed attempts, formatting/ownership/privacy checks and preservation. It does not qualify initial/no-source selection, unavailable-source/data choices, all crash phases, live inactive legacy migration, removal/retention controls, P8 UI/notifications, a real newer SDK, b47380-to-final, managed/installed/frozen delivery, production catalog deployment, other platforms, power/disk loss or load/performance. The original broker/transport load failure remains unproven. The full P0–P10 objective remains unfinished; work continues.
