# CIGAR runtime selection routing and update walkthrough

Status: locally implemented and fixture-browser checked 2026-10-28; partial P8. See [the Versions UI checkpoint](CIGAR_VERSIONS_UI.md) and [receipt](evidence/upgrades-versions-routing-20261028.json). Native initial/reset/clearing APIs and the full P6/P7/P9/P10 matrix remain unfinished.

## Selection stays with its owner

Runtime & preferences now displays the native selected installation and offers Choose or switch runtime. The button opens Versions & updates through Guard's existing same-document navigation event, retaining the form, connection parameters and browser history. It performs no preparation or selection. Feature, source and resource preferences remain editable in their existing form. Runtime IDs are no longer offered as ordinary draft options. A draft left by an older UI can restore just the current runtime choice without discarding other preference edits.

The workspace listens to the shared dashboard-location event and popstate. The native owner still verifies, prepares and explicitly commits every selection exposed by this UI. UI routing does not make the older native initial/clear/reset entry points complete; their remaining data-choice/recovery work stays required.

## Learning progress remains separate

A new six-step Update CIGAR with less interruption walkthrough covers exact build/host qualification, preparation beside the current runtime, selection readiness, explicit switch/reconnect consent, fresh source/app grants and last-good rollback/recovery. It uses real Versions controls and reports the live native state; reading or advancing never invokes an action. Existing tutorial IDs, step bounds and session progress schema/key remain valid. Only one outdated first-brief instruction changes; the guide now sends runtime selection to Versions. The lesson data lives in a separate module.

## Preference equality

Native status and general settings can serialize identical object keys in a different order. Comparing raw JSON strings could falsely report a native preference change and overwrite a pending edit while CIGAR was off. The shared selection merge now compares recursively ordered JSON, without changing values or mutating inputs. Captured status publication and dirty-state checks use the same equality. Tests prove that reordered metadata leaves a pending opt-in and saved off preference unchanged. Actual native changes and a later Stop still retain their existing stale-response and opt-out protections.

## Verification and limits

Four routing/settings/workspace/tutorial assertion modules pass. The two affected merge/routing modules pass after the equality fix. Strict checking retains exactly the same thirteen pre-existing shared diagnostics in hash-verified unchanged files, with zero new diagnostics. Fourteen isolated browser checks pass, including the new picker navigation, walkthrough navigation/resume with no effects and reordered-metadata draft regression. Dashboard utility styles and 390px page width are asserted. The first walkthrough query timed out because it assumed adjacent inline text around the colon; the fixture query was corrected without changing the product label. Its failed receipt remains recorded.

Exact inverse goal patches reproduce all seven affected workspace/tutorial files' original dirty bytes. Of the original84 paths,75 remain byte-identical, seven contain only the recorded goal changes, and two retain the earlier documented intentional differences. Native Rust, Python runtime and lock sources remain exact to the prior UI checkpoint; its native and real SDK checks retain their original images/scope. All seven approved SDK/interpreter inputs are rehashed unchanged. No live Guard, hook, profile, preview, system Python, upstream SDK, Git staging/history or publication changed.

This browser suite intercepts every Guard API response and does not qualify native/SDK/installed operation. Notifications and automatic preparation remain unavailable, preview installation remains unsupported, and production catalog trust/feed/qualification is not provisioned here. Complete unavailable/withdrawn-source and reset/data-choice routing, selected-source/process-loss recovery, inactive legacy scopes, removal/retention, full accessibility and remaining P9/P10 real newer/candidate-to-final, managed/installed/frozen/platform/approval/load/performance/bump evidence stay required. Earlier SDK workspace and broker/transport reliability observations remain open. The full P0–P10 objective is unfinished.

## Follow-up: optional false defaults

Known optional execution_context flags now compare absent and false equally, so a Guard metadata/default change cannot erase a pending edit. True remains distinct. Focused tests and the fourteen-case v9 browser receipt pass; the same13 prior shared type errors remain. See [the recovery checkpoint](CIGAR_DISABLED_RECOVERY.md) for the updated native evidence and remaining scope.

## Recovery details and accessible build cards

[The Stop-recovery follow-up](CIGAR_STOP_RECOVERY.md) distinguishes recovery/preparation deadlines, labels selected/running/core state and adds accessible build names/descriptions. Sixteen isolated browser checks pass, including keyboard edits/focus without native effects. Complete assistive-technology and installed/native/browser qualification remain required.
