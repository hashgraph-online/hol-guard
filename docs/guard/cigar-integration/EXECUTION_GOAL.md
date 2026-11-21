# Full CIGAR integration execution goal

Status: **authorized local P0–P5 acceptance verified, 2026-10-25**. See [acceptance and release limits](ACCEPTANCE.md). Requested execution profile: **GPT-6.1 Sol**. This specification is written for that model; the goal tool itself does not select or change the active model.

Implement and validate a working optional CIGAR 0.14.1 integration in this checkout, on local branch `feature/integrate-cigar-0.14.1`. Start from HOL Guard v3.55.1 (`35180b995cb27fdc9f92e1f68307a756c785f154`) and the analysis commit `f69fd57e`. The read-only CIGAR candidate source is the sibling `hol-cigar-0.14.1-security`, initially verified at `b47380e5a5cbeaaad5a61cab3372e9e67368732f`.

The deliverable is a functioning product integration with reproducible evidence. A plan, a capability stub, mocked UI, isolated SDK demo, or partial phase does not satisfy this goal.

## Operating instructions

Read `~/.hol-support/SAFETY.md`, applicable `AGENTS.md`, [native ownership](../native-hook-data-plane-ownership.md), [approval invariant](../approval-invariant.md), and the [integration analysis](../../../CIGAR_INTEGRATION.md). Inspect the actual source before changing it. Existing analysis is a starting specification; update it when implementation evidence requires a better design.

Work locally in this checkout and authorized temporary directories. Preserve unrelated user changes and the CIGAR source baseline. Make small coherent commits after meaningful checks. Do not push, release, publish, deploy, change the live Guard installation, access credentials/environment files, or rewrite history. Explicitly identify package/version/workspace when dependency work is necessary. Do not replace CIGAR 0.14.1 with another release to make installation easier.

Public release availability and platform receipts must be checked before public activation. An unpublished artifact does not prevent local implementation and qualification using the exact local candidate. Record the qualification scope rather than making all progress depend on publication.

Keep [EXECUTION_LOG.md](EXECUTION_LOG.md) current after each meaningful checkpoint: implemented behavior, tests and their results, relevant artifact/commit identities, remaining limitations, and the next concrete action. On resumption, inspect the log and Git state before continuing. Never infer completion from an earlier commentary message.

## Required invariants

1. **Explicit opt-in.** Context assistance is off when configuration is absent. Global enablement does not grant every app, workspace or source access. Turning off revokes assistance scopes and stops optional workers; it leaves Guard approvals under their existing rules.
2. **Actual Python 3.14 gate.** The selected CIGAR process must be qualified final CPython with version tuple exactly `(3, 14)`. Reject other versions, prereleases, unsupported implementations/builds/ABIs and unqualified process targets. Check the matching approved SDK, bundled worker bytes, protocol and required features. A filename, browser, parent interpreter or caller assertion is insufficient.
3. **Base compatibility.** Preserve Guard's existing Python >=3.10 installations. A separately selected, verified 3.14 environment may run CIGAR while Guard runs another supported version. Do not change the system's default Python or silently install Python/packages.
4. **Backend enforcement.** Enforce eligibility and effective state before worker creation, ingestion, compile, sharing and action associations. Test direct HTTP, CLI, MCP, cached tool and override calls. A persisted enabled bit or hidden switch is not authority.
5. **Native authority.** Rust owns configuration validation, availability, source I/O, scope/policy, supervision and deterministic control. Python is thin public-SDK/transport glue. Do not introduce a parallel Python evaluator or bypass the ownership gates by moving code to another directory.
6. **Approval compatibility.** Every supported review retains Allow once and Always allow. Honor saved approvals until removal or a genuine existing action/hash change. CIGAR failure, stale sources, missing reviews and worker outages never veto an approved command or change existing native fail-safe behavior.
7. **No blocking hook dependency.** No mandatory CIGAR call, import, runtime probe or source scan on the synchronous hook path. Native reasons and approval controls remain immediately usable. Preserve native evidence ordering, acknowledgements and required state independently of optional assistance queues.
8. **Scoped evidence.** Derive identities from authenticated Guard sessions and canonical host/workspace state. Admit native facts and sanitized receipt facts only after opt-in. Extra documents need explicit source selection and protected Rust reads. Exclude secret/environment/credential material, escaping symlinks, unstable/invalid/unbounded files and unrelated scopes. Source locators do not open files.
9. **Honest context.** Keep exact revisions/provenance, dependency/counterevidence closures, snapshots and citations. Reject foreign, stale, expired or revoked contexts. Retrieval signals do not prove truth or safety. Start with deterministic native facts and attributed excerpts; free-form model prose requires independent trusted review and separate disclosure controls.
10. **Bounded lifecycle.** Bound jobs, bytes, graph/worker counts, queue waits, execution deadlines and retention. Keep unknown write/send outcomes unknown until reconciled. Do not blindly retry a mutation after transport failure or accumulate timed-out work in unbounded threads.
11. **Host-owned sharing.** Keep broker ingestion, grants, admission, review and policy on the host. Deliver secrets only through protected application IPC, never browser payloads, prompts, argv, environment, logs or shared settings. Logical views are not OS isolation.
12. **Recovery and privacy.** Persistence may restore admitted evidence, not credentials/tickets/drafts/reviews/execution permissions. Restart with fresh authority. Keep private snapshots/text out of ordinary diagnostics, telemetry and cloud receipts. Report measured efficiency and limitations without unverified exponential, truth, replay or memory claims.

## P0 Runtime eligibility and configuration

- Implement a small native typed configuration and capability boundary, with strict schema/default/range/cross-field validation and managed restrictions.
- Keep requested enablement separate from effective availability. Use bounded, actionable reason codes and generations bound to runtime/package/worker/policy identities.
- Discover selected interpreters on the control plane, validate the executable and its protected identity, run an isolated bounded probe before SDK import, and verify package/worker/handshake plus a synthetic compile.
- Expose host status, explicit recheck and setup/repair operations using existing daemon/CLI authentication and settings write protections.
- Keep optional control preparation and request budgets explicit: existing native readiness probes retain their five-second normal/twenty-second first-probe bounds; after readiness, the control RPC has two seconds including queue wait. Total optional control wall time can include both phases. Hook and workspace preparation budgets stay unchanged; never retry an unknown mutation to hide a timeout.
- Extend native config load/update/import/export/reset, Python projections and TypeScript types together. Do not treat an optional dependency marker as runtime enforcement.
- Define an explicit, version-bound bridge package and isolated environment path. Account for frozen Desktop executables and use existing artifact verification conventions.
- Test unavailable/off behavior before enabling content operations.

Completion: all unsupported/forged runtime paths refuse assistance, base Guard startup remains independent, and real qualified candidate verification works in an isolated local installation.

## P1 Context runtime and evidence flow

- Implement a persistent SDK bridge using public `cigar_sdk` graph/view/broker APIs, and a Rust supervisor with private versioned bounded IPC.
- Implement deadlines, identity generations, shutdown, bounded restart/circuit behavior, per-workspace graph limits and idle eviction. Use a sanitized environment before launching the SDK worker.
- Implement explicitly selected source admission, stable safe reads, line preservation, withdrawal, revision/provenance, narrow app/session views and cache invalidation.
- Compile mandatory native action/policy facts and complete dependencies within explicit budgets; validate snapshots/citations at use and degrade to native-only review when unavailable.
- Subscribe to post-admission native evidence through a separate optional notification path. Do not repurpose the placeholder enrichment queue or steal native evidence acknowledgements.
- Coalesce optional jobs and test overflow, stuck workers, source churn and unknown mutation outcomes.

Completion: actual installed SDK/worker produces current cited context from authorized sources, rejects stale/foreign sources, and can fail or stop without changing ordinary native decisions/approvals.

## P2 Product screens and controls

- Implement actual React screens using existing components: Home status; Settings → Protection subsection and onboarding; app/workspace/source access; review brief/source drawer/change comparison; Evidence historical context association; Data & repair.
- Keep the current six settings tabs and existing approval payload/actions. Load the assistance panel independently without moving/disabling approval controls.
- Show host availability and clear Python 3.14 guidance. Present meaningful resource presets and effective scopes; hide advanced protocol details unless useful.
- Support explicit enable, disable, recheck, source withdrawal, revocation, cache clear and separate saved-data removal through real backend operations.
- Test keyboard/focus, narrow layouts, accessible disabled reasons, stale/pending/failure states and honest requested/dispatched/confirmed execution copy.

Completion: a user can configure, use, inspect and turn off assistance end to end with a real backend, while ordinary approvals work during every assistance fault.

## P3 Agent planning assistance

- Add scoped status/context/action-explanation tools through the shared typed MCP registry, direct-call dispatch and FastMCP registration.
- Use one trusted availability/scope contract across discovery and calls. Withdraw executable tools when disabled and refuse cached calls explicitly.
- Derive caller authority from authenticated host sessions, not requested app/agent/workspace identifiers.
- Qualify real installed harness routes; report partial capability when a harness cannot accept context/tools. Guidance is data for a later tool request, not execution permission.

Completion: a qualified agent retrieves authorized current evidence before planning another tool call, without receiving broader sources, broker credentials or automatic approval.

## P4 Independent agents and persistence

- Implement separately enabled `LocalContextBroker` mode, protected grant delivery, finite leases, per-agent limits/fair queues, revocation and host proposal inspection/admission.
- Test conflicting source/proposal writes and preserve revision strings exactly. Recovery invalidates old grants and contexts.
- Implement optional local private persistence with enforced retention/withdrawal/deletion, proper Unix or qualified Windows protection, bounded checkpoints/journal/disk use and unknown-write reconciliation.
- Keep default memory-only behavior. Never restore execution authority or represent graph scopes as hostile-tenant isolation.

Completion: real independent clients share only allowed sources with bounded lifecycle, races and recovery verified; persistence restores evidence with a new authority epoch.

## P5 Exact action association and execution handoff

- Associate the retained context with Guard's exact native action identity as advisory evidence, without changing existing command hashes or approval semantics.
- Revalidate recommendations and proposed new work against current scope/evidence.
- Use advertised, installed-qualified `execution_handoff.v1` only through a real Guard executor adapter that preserves existing authority, exact intent and uncertainty behavior.
- Prove source/reviewer/intent changes, revocation, one-time consumption, restart and ambiguous send/consume outcomes. Never insert an extra veto into an already approved command or claim atomicity across an unproven send boundary.
- Keep the separate Honey effect service and `dispatch_context_effect` optional; it is not automatically Guard's executor.

Completion: native action/context associations and each supported handoff route have actual integration evidence and preserve every existing supported approval choice.

## Verification and completion definition

Test valid final 3.14 and missing/older/newer/prerelease/alternative/unqualified runtimes; false executable names; changed identities; absent/wrong SDK or worker; direct-caller bypasses; managed restrictions; separate Guard/CIGAR environments; off-state inactivity.

Test secret/path/permission/race/encoding/size controls, empty/foreign/revoked scopes, exact revisions/citations, required closures and compilation limits, source changes, native-only degradation, queue overflow, finite timeouts, restart/generation changes, multi-agent conflicts, persistence and execution uncertainty. Use existing negative/parity fixtures and meaningful new behavioral tests.

Run the applicable Rust/Python/frontend checks, native semantic/I/O/privacy ownership gates, schema/version/generated projection checks and actual installed local candidate path. A mock-only pass is not installed qualification. Record exact artifact hashes and unrun platform checks. Unqualified platforms remain unavailable.

Retain existing direct and installed SLO/RSS thresholds. Compare feature-off and feature-on revisions on the same measurement boundary, include background compilation contention, report all bridge/worker memory, and measure source reuse plus useful review/agent outcomes. The proposed extra warm-p95 threshold is no regression beyond `max(1 ms, 5%)`, while existing absolute gates also pass. Do not claim a gain from a ceiling-only test.

Demonstrate actual opt-in → source admission → cited review → scoped agent context → source update/stale rejection → disable/revoke/cleanup, followed by sharing, persistence and supported exact-association/handoff paths. Demonstrate normal base Guard operation without CIGAR and with unsupported Python.

Update architecture/setup/repair/user/developer documentation and release checklist. Retain reproducible evidence, verified local commits and a clean working tree. Mark the goal complete only when all authorized local phases work and their required checks pass. Explicit external signing/publication/platform release gates may remain identified, but must not be falsely claimed complete or used to avoid independent implementation work.
