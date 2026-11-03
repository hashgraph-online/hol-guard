# Update preferences and exact-build pins

CIGAR update intent now has one native profile settings owner. Changing an update pin, channel or notification preference does not change the serving SDK configuration. The real final 0.14.1 test preserves the same actor, native generation, authority epoch, reviewed notes and an existing SDK snapshot across preference edits. An explicit acknowledged switch still owns the interruption and fresh application/source grants.

## Profile and policy contract

The profile stores a separate `[context_assistance_updates]` table in `config.toml`, outside `ContextAssistanceConfig`. It uses the existing protected config reader, short writer lock and exact-byte publication. Other settings/comments and enabled/off intent survive writes. A general settings save preserves this table; an explicit full settings reset resets it with other local preferences. Runtime configuration equality and ordinary activation settings contain no update-preference field.

The shared release crate owns strict preference types and managed restriction composition. Defaults are manual updates, stable releases, no local pin and retained last-good recovery bytes. Unknown keys, wrong types, malformed build IDs and unsupported modes refuse. Pins name an exact catalog build ID, independently of its SDK version; a same-version rebuilt artifact can therefore have a different eligibility result.

Native operator reads resolve current machine policy with cache writes disabled and report requested/effective preferences, relevant locked paths, diagnostics, revision and capabilities. Machine policy can narrow optional work and preview consent, require an exact build pin, and require recovery retention. It cannot turn a local manual preference into optional background work, opt a stable-only user into previews, clear a local pin through a missing/null requirement, force deletion or enable CIGAR. A conflicting locked requested field refuses publication. Invalid update settings prevent new supported selection work and remain an update-specific diagnostic; they do not rewrite the SDK preference table.

The writer requires the exact revision returned by a preference read. The revision binds configuration presence and raw bytes; it is a conflict token, never an approval or SDK grant. Another settings edit or repeated Stop makes an old revision stale. Publication refuses rather than rebasing over that edit. The native owner resolves machine policy itself; requests cannot replace it with caller-supplied authority. A profile read does not create an installation, preparation store, activation job or serving actor.

## Selection boundaries

Live switch preparation checks the target's exact release binding against the effective pin and the authenticated catalog's channel. Ordinary settings opt-in or runtime-ID replacement checks the same rules outside the short writer lock, while retaining its shared lifecycle lease. SDK/interpreter/receipt verification, permanent withdrawal checks and qualification remain separate requirements; a pin never approves bytes.

A switch captures effective update preferences together with the existing SDK/settings snapshot. Native preflight and target publication recheck them against current machine policy. A local preference edit changes the captured bytes; a policy-only pin change also invalidates the prepared choice. A pin edit while Ready therefore rejects cutover before stopping the source. Preference writes deliberately use only the short writer lane and remain possible while a Ready job owns the lifecycle lease.

Pins constrain supported selection changes. They do not force an installed/selected runtime to switch, stop a healthy actor, revoke existing source scopes or replace the installed-selection offline rules. Existing current-runtime Start/recheck behavior remains separate from a new selection. Advanced external config edits are outside the supported writer protocol and remain subject to native selection/data recovery and artifact verification; full off-state SDK/data selection and its admission matrix are still required.

Stable/preview is represented by `allow_preview`; allowing preview never overrides catalog trust, qualification, adapter support or explicit selection. Legacy operator enrollment remains its separate advanced path and is not reclassified as a public release. A build pin cannot be satisfied by a legacy record without the matching catalog release binding.

## Native, CLI and HTTP

| Action | Fields | Result |
| --- | --- | --- |
| preferences | none | Passive requested/effective policy, exact revision and available controls. |
| set_preferences | expected_revision, preferences | Protected whole-table update, without installation, selection or activation. |

Root and nested CLI commands now include `context preferences`, `context pin BUILD_ID --revision REVISION`, `context unpin --revision REVISION`, and `context update-policy --mode manual|notify --channel stable|preview --revision REVISION`. Pin/unpin/policy framing reads current native requested fields to preserve the others and sends the caller's original revision unchanged. A newer read never silently upgrades a stale user's write. JSON and human output render the same native result. Reload preferences after a conflict.

Both actions use the existing operator-authenticated versions transport. POST `/v1/context-assistance/versions` carries the input action; preference reads need no expansion proof, while writes retain the existing settings approval gate. Proof stays outside the native CIGAR input. Paired context consumers gain no administration capability. HTTP reports revision and locked-preference conflicts as conflicts. Existing fixed GET routes cannot smuggle a preference mutation.

Automatic preparation, automatic switching, retention reduction and safe managed-slot removal are not implemented by this checkpoint. The native capability result reports those limits, and the writer refuses `mode=prepare` or `retain_last_good=false` without writing. `notify` currently records presentation intent; notification delivery and the Versions & updates presentation remain P8 work. Saving it does not start refresh, downloads, scanning or SDK work. These limits preserve the remaining full objective; this is partial P7 acceptance.

## Verification and remaining scope

The release crate passes 59 tests on stable Rust and Rust 1.88, and its all-target Clippy check passes without warnings. Native configuration passes 55 with one internal process-loss helper ignored. Seven preference cases cover passive defaults, actor-settings/off-state preservation, stale edits/repeated Stop, current machine caps/locks, explicit repair, unsupported work and invalid policy. Seven native switch-policy cases include a policy-only pin change with byte-identical config. Registry 119/5 SDK gated, Service 17/14 SDK gated, off-state saved-data 10, route authorization 10 and optional-work lane 15 pass separately. Python framing passes 86, with Ruff and formatting checks. Counts overlap and are not summed.

The new actual SDK case uses final 0.14.1, external CPython 3.14.7/3.14.10 and test-only catalog roots/qualification. It preserves an active actor/epoch/notes/snapshot during pin writes, refuses a mismatched live preparation and ordinary settings selection, rejects a changed Ready choice before source interruption, and completes an explicitly acknowledged switch under the matching exact pin with notes intact. Stop plus passive preference inspection leaves CIGAR off. The prior authenticated-catalog ordinary opt-in and live refresh/re-verification/switch/latest-data rollback cases also pass on the same final native image.

[Evidence](evidence/receipts.json) binds current sources, inputs, images, logs and preservation. Native Rust 1.88 compilation and authority/I/O/privacy gates pass. Runtime Clippy retains 36 baseline errors in 23 hash-verified unchanged sources, zero new errors, and two unused production helpers. Cargo.lock and original SDK/interpreter inputs are unchanged. No matching test bridge/broker/switch process remains after validation.

These are local macOS ARM64 test-image native requests and mocked Python framing, not installed CLI/HTTP-with-SDK or frozen delivery acceptance. They do not qualify b47380, a real newer SDK, managed-Python end-to-end, production feed/trust, other platforms or concurrency/load/performance. The original broker/transport load failure is not proven resolved. P7 cold off-state SDK/data selection, removal and retention work; P8 notifications/UI/walkthroughs; the remaining P6/P9 crash/cleanup/data-choice/approval-isolation matrix; and P10 installed/frozen/platform/maintainer-bump qualification remain required. Original workspace/tutorial work, integration acceptance/log, live profile/hooks/preview, system Python and upstream SDK sources remain preserved. The full P0–P10 goal remains active and incomplete.
