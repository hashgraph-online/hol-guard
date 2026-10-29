# CIGAR Versions & updates UI checkpoint

Status: locally implemented and fixture-browser checked on 2026-10-28. This is partial P8, with no installed HTTP/SDK-process or cross-platform qualification implied. See [the plan](CIGAR_UPGRADE_PLAN.md) and [receipt](evidence/upgrades-versions-ui-20261028.json).

## User workflow

The CIGAR workspace has a keyboard-accessible Versions & updates tab alongside the existing runtime, sources, data and tutorial sections. Opening it reads native catalog, interpreter, installation, preference and job metadata. It never probes Python, imports CIGAR, downloads packages or starts an SDK.

Users can explicitly refresh/import authenticated catalog metadata, prepare private Python or an SDK alongside the selected runtime, prepare an installed selection or the last good build, cancel work, recover interrupted jobs and commit a native Ready selection. Build IDs and source/manifest identities distinguish same-version artifacts. The platform comes from the Guard host, never the browser. Native withdrawal, qualification, freshness, pin and managed-setting information is retained; an upstream-only artifact is not presented as ready to install.

Preparation does not select or activate a runtime. Live commit requires reconnect acknowledgement and the exact native generation string. Initial/off-state commit keeps CIGAR off and sends reconnect=false. Native admission remains authoritative. Long preparation does not lock the whole workspace or its Stop control. Job progress, IDs, diagnostics and explicit recovery are visible. Unknown transport outcomes are not automatically retried; refresh jobs before another change.

Existing settings proof is carried outside SDK input. Read/cancel operations carry no unnecessary proof. A captured request revision prevents an older versions response from undoing a later Stop. Selection synchronization changes only CIGAR's saved baseline; unrelated settings and pending CIGAR edits survive, including an explicit opt-out. A newer saved preference or separately chosen draft runtime is not overwritten.

## Module boundaries

Transport, catalog/preferences/interpreter/job projections, metadata loading, asynchronous controls, action availability, settings merging and individual views are separate modules. The Versions panel composes them and owns the existing proof modal. The native releases projection adds passive host-platform metadata by sharing the existing Python setup platform mapping; supported platforms and admission rules are unchanged.

The four existing workspace/settings files receive exact additive wiring. Inverting those recorded additions reproduces their original dirty bytes. The pre-existing large settings workspace receives only callback/import/prop wiring; no unrelated refactor is included.

## Verification and limits

Nine frontend assertion modules pass; only the two test files corrected for TypeScript literals were rerun afterward. Separate catalog/identity/history/model checks pass. Strict checking of the wired settings import graph and new tests has exactly the same thirteen diagnostics as the original graph in hash-verified unchanged shared files. Whole-dashboard TypeScript remains non-green.

The reusable dashboard/scripts/cigar-versions-browser.mjs launches a private browser and ephemeral localhost server, intercepts every Guard API request and blocks other origins. It accepts an optional installed browser executable and new output directory; it never downloads a browser. Eleven checks cover passive opening, keyboard navigation, explicit reconnect consent, precise generation strings, draft preservation, delayed-reply/Stop ordering, no mutation retry, off-state initial selection, existing proof separation, cancellation, stale jobs, explicit recovery and a 390px layout. Generated dashboard utilities and absence of horizontal page overflow are asserted. This fixture suite is not actual SDK or installed Guard acceptance.

Native host metadata is checked by the 138-pass/5-gated registry suite and Rust1.88 production compile. Formatting and authority/I/O/privacy gates pass. Native Clippy still reports36 prior errors in23 hash-verified unchanged files and zero new errors. The current native test image is29eb21592c01f8202b250c6d4870a84c6df4bc4fd4cbeca73245bef9a1c8982a; prior real SDK evidence remains scoped to e5969592efb0e7785ff896c1e252b84d5e50cddf18551857f1d5a03b41d14541 and is not relabeled.

The first browser harness failed before rendering because an absolute React import bypassed dependency conversion. The second correctly rejected incomplete adapter metadata in a fixture. Both failures remain recorded. Two new test-only TypeScript literal errors were corrected. Later browser passes added cancellation/recovery and explicit utility-source/style assertions. Milestone staging also encountered a Python quoting syntax error before writes. No production validation was relaxed.

Notifications are not delivered and automatic preparation/selection remains unavailable; the UI says so. Preview installation remains unsupported in the current native install path. The old ordinary runtime selector/reset/clearing paths still need full routing/data-choice work. New walkthroughs, complete accessibility acceptance, unavailable/withdrawn-source choices, selected-source/process-loss recovery, inactive legacy live scopes, removal/retention and remaining P9/P10 real newer/candidate-to-final, managed/installed/frozen/platform/approval/load/performance/bump qualification remain required. Production release trust/feed and qualification are not provisioned by this UI. The earlier SDK workspace timeout and broker/transport load failure remain unresolved. The full P0–P10 objective is unfinished.

## Follow-up: selection routing and walkthroughs

[The routing follow-up](CIGAR_VERSIONS_ROUTING.md) replaces ordinary runtime draft selection, adds a six-step resumable update walkthrough and makes preference comparison independent of JSON key order. Fourteen fixture-browser checks pass, including a pending-edit regression. This supersedes the earlier UI-picker/walkthrough gaps above; native initial/reset/clearing/data-choice routing, notifications and full qualification remain required.
