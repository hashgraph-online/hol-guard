# Takeaway Prompt: Build Browser Protection and Provider Integrations in HOL Guard

Complete `docs/guard/browser-protection-prd.md` and `docs/guard/browser-protection-todo.md` in
`hashgraph-online/hol-guard`.

Read both documents in full before changing anything. The PRD holds the design, the invariants and the
verified baseline. The TODO holds the work items (`BP-T###`), their file targets and their evidence.
This prompt tells you how to work through them.

## Mission

Agents reach browsers through MCP servers, harness built-in tools, shell launches and raw DevTools
protocol connections. Today Guard classifies only a few name-matched MCP servers, asks again for every
new click target, has no site-level grant or denial, and cannot be extended for a new browser tool
without editing Rust tables. There is one bespoke vendor integration and no general way to add another.

**Guard is the place to integrate, not the detector.** Many products already sell web protection
directly to people and teams: safe browsing, anti-phishing, download scanning, script protection,
privacy governance, enterprise browser policy. None of them can see or stop what an agent is about to
do in a browser. Guard can, because its hooks fire before the action and its approval card is where
the user decides. Your job is to build that position into a contract any of those products can plug
into with a manifest and a review. You do not build reputation feeds, script analyzers or classifiers
here, and you do not write code for one named vendor. "ExampleShield" in the PRD is a stand-in for all
of them.

Two failures count equally: a protected browser effect that happens, and a prompt the user did not
need. A browser task is dozens of actions. If a routine task costs more than one card, or a connected
provider makes ordinary work louder, the work is not done.

Deliver two things:

1. **Provider integrations.** A declarative, reviewed contract that lets any security vendor add
   browser evidence to Guard. A user connects it with their own account or API key, bought from the
   provider directly. The key stays in the resident. Several providers can be connected at once.
   Signals appear on the approval card and can tighten decisions. They can never loosen one. This is
   the more important half.
2. **Layered browser protection.** One native browser action model fed by contributed driver profiles,
   covering launch, tool call and protocol layers, with site and session grants, site denials, a
   native-typed approval card, and a Browser area in Protection Center.

Committed scope is phases 0 to 3 of the PRD. Phase 4 (protocol table and relay) starts only after its
ADR is accepted. Phase 5 is an ADR only.

## Read first

| Document or module | Why |
| --- | --- |
| `docs/guard/approval-invariant.md` | Every browser review must keep Allow once and Always allow. Read before touching grants, scope contracts or the card. |
| `docs/guard/command-extension-architecture.md` | Contributions emit evidence only. Monotonic decision composition. Closed native operation set. |
| `docs/guard/mcp-server-contributions.md` | External and opt-in trust model, evaluation order, review bar that driver profiles and providers inherit. |
| `docs/guard/extension-control-center.md` | Routes, densities, safety invariants, preview plus one-use proof. |
| `docs/guard/native-hook-data-plane-ownership.md` | What Rust owns. No new Python runtime logic. |
| `docs/guard/yanez-pulse-approval-gate.md`, `rust/crates/guard-yanez-pulse/` | The key-custody, pinned-host, capped-body pattern to generalize. Do not change Pulse behavior. |
| `docs/guard/adr/0015-cloud-action-facts-ownership.md`, `0016-brokered-sign-in-transport.md` | Declarative provider request rendering and the closed-list approach. |
| `rust/crates/guard-contracts/src/browser_mcp_intent.rs`, `rust/crates/guard-command/src/browser_mcp_intent.rs`, `browser_mcp_patterns.rs` | Current intent model and the static tables you migrate. |
| `rust/crates/guard-runtime/src/temporary_mcp_grant.rs`, `guard_store_temporary_mcp.rs`, `mcp_tool_policy_flow.rs` | Grant targets, eligibility, covered-request resolution. |
| `rust/crates/guard-runtime/src/daemon_edge_discovery.rs`, `discovery_placement_op.rs` | Fixed-origin managed egress, rollback switch, placement id namespace. |
| `rust/crates/guard-command/src/egress_caller.rs`, `egress_caller_policy.rs` | Managed network policy for every outbound provider call. |
| `dashboard/src/mcp-call/`, `dashboard/src/temporary-mcp-approval*.ts*`, `dashboard/src/pulse-*.tsx` | Card, grant controls and the connect flow to model on. |
| `AGENTS.md` | Public-text rules, synthetic names, review policies. |
| `ci/gauntlet/README.md` | The qualification rules you must follow: what a pass requires, "ordinary work must be silent", the interruption definition, outcome codes, known gaps, the model-free replay lane, release budgets, case authoring. |
| `ci/gauntlet/catalog.py`, `lane_coverage.py`, `release_budgets.py` | The closed oracle and field sets, the lane and profile lists (`QUALIFYING_LANE`, `PROFILES`, `_HARNESS_ONLY_PROFILES`), and the budget rows you extend. |
| `ci/gauntlet/connector_setup.json`, `connector_fixtures.py`, `connector_judge.py`, `mcp_calls.py` | The closest precedent: a harness-only profile with a synthetic stdio MCP server and its own judge. Model the browser profile on it. |
| `ci/gauntlet/approval_retry.json`, `approval_retry.py` | How a case answers a review card and retries. Browser grant round trips go here. |
| `tests/fixtures/benign_false_positive_gate.json` (`mcp_cases`), `tests/benign_fp_gate_mcp.py`, `tests/test_guard_benign_false_positive_gate.py` | The deterministic gate in ordinary CI. Every pinned browser decision is a row here. |
| `tests/fixtures/gauntlet_replay_cases.json`, `tests/test_guard_gauntlet_replay_gate.py` | Recorded harness payload shapes with `quiet`, `always` and `block` expectations. |
| `tests/test_gauntlet_native_commands_in_fp_gate.py` | The pattern for "every live allow case is mirrored in the gate". |

## Required architecture

- Rust owns classification, matching, grants, signal evaluation, secret handling, provider HTTP and
  protocol parsing. Python is argument parsing, rendering and calls into the native runtime.
- One native `BrowserActionV2` is the input to every browser decision and every card. The dashboard
  renders the native `BrowserCardV1`. It does not infer meaning from tool names.
- Driver profiles and provider manifests are data: literal lists, closed enums, JSON pointers. No
  regex, script, WASM or downloaded detector. A real semantic gap gets a reviewed Rust operation or
  adapter.
- Native sensitive-surface screens run on every browser call and cannot be cleared by a profile. An
  unlisted tool is `unclassified` and reviewed. An unknown protocol method is privileged.
- External profiles and providers are inert until a local-admin enable. A this-device custom MCP grant
  still wins over a contributed default.
- Every browser review offers Allow once and Always allow. Site and session grants, the durable
  per-site choice and "Block on this site" are additional choices. Deny is always visible.
- A grant never follows a cross-origin navigation. Shared-profile sessions get only the narrow
  `session-site` grant with the exclusions in the PRD.
- A browser action aimed at Guard's own approval origin is a block. An approval page never opens
  automatically in a browser the agent is driving.
- Provider signals are evidence. `ok` changes nothing. `caution` and `danger` tighten. Only a user or
  administrator setting turns `danger` into a block. Nothing a provider returns can allow, grant,
  shorten a review or lower a floor.
- The decision path reads the local signal cache only. No provider network call on the hook or relay
  path. A worker fetches signals off the hot path under a token bucket and circuit breaker.
- Provider outage never weakens and never blocks by itself: same decision as with no provider, plus a
  finding.
- The provider key is written once, held zeroizing, stored through `encrypted_secret_store`, and never
  returned to Python, the dashboard, an agent, a log, a receipt or telemetry.
- Only the closed fact set leaves the device, exactly as declared in the manifest's `shares`, and never
  for loopback, private or reserved-suffix origins.
- Provider HTTP is HTTPS to an exact pinned host, no redirects, capped bodies, strict JSON, under the
  managed network policy.
- Sponsorship changes placement and a disclosure label only. The runtime has no field for whether a
  provider pays. The label comes from a live validated placement.
- Guard builds no web threat detection. Its own browser rules are limited to what it can prove locally
  from the action. Everything else is a provider's answer to one of the fixed moments in PRD 6.1.
- Every browser action is in one of three classes (PRD 5.10). Quiet: no card, no rendered text, no
  approval row. One card: a review that offers Allow once, Always allow and a grant that covers the
  rest of the task. Protect: reviewed or blocked every time. The class of each reference driver tool
  is pinned by a gate row.
- An action covered by a live grant, a saved allow or an answered card never asks again. A retried
  call attaches to its pending row. Several pending rows for one site, or several unknown tools on one
  driver, show as one card.
- Routine actions on a loopback development origin in an isolated or dedicated profile are quiet, with
  the exclusions in PRD 5.10 (open decision D10).
- A provider cannot add prompts by existing. With a provider answering `ok`, `unknown` or failing,
  every decision equals the no-provider decision. An unverified provider's `caution` is a finding
  only. Provider-caused reviews are capped per subject and per session. The user can lower any
  provider effect to observe-only, never below Guard's own decision.
- Several providers on one subject produce at most one review. The strongest fresh verdict wins.
  Placement never orders the rows.
- The only test hook in a release build is the provider fixture origin, with every restriction in PRD
  8.3 enforced by a test.
- Every new capability, fact, verb, grant target or risk category is a contract change with tests, not
  a string added in passing.
- Both rollback switches (`HOL_GUARD_BROWSER_PROTECTION=legacy`,
  `HOL_GUARD_PROVIDER_INTEGRATIONS=off`) restore prior behavior.

## Implementation order

1. Read the PRD, the TODO and the "Read first" table. Confirm the baseline in PRD section 2 against
   current `main` and note anything that moved. Update the PRD when a referenced file or symbol has
   changed; do not work from a stale reference.
2. Phase 0: ADR 0018, the ADR 0017 design gate, contracts, schemas, contribution directories, trust
   and packaging plumbing, rollback switches, baseline measurements (BP-T001 to BP-T009).
3. Regression harness, before any decision changes: the fixture driver and stand-ins, baseline gate
   rows that pin what current `main` decides, replay shapes, the `browser` Gauntlet profile with its
   oracles and judge, the pairing and coverage tests, the budget rows (BP-T160 to BP-T167). Land the
   baseline rows in their own pull request. From here on every pull request that changes a decision
   adds its Rust test, gate row and live case, and shows the class change as a diff.
4. Phase 1, classification: driver compiler, matcher, projection, first-party table migration with
   parity vectors unchanged, then the reference driver set, harness built-ins and the eval facade
   (BP-T010 to BP-T027).
5. Phase 1, launch and self-protection: the browser automation command source, session debugging
   ports, the Guard-origin block (BP-T030 to BP-T036).
6. Phase 1, card and catalog: native card projection, dashboard card, catalog surface and kinds,
   `browser explain`, Extension Builder (which also emits gate rows), contributor guide, phase 1
   Gauntlet cases and latency evidence (BP-T045 to BP-T059).
7. Phase 3 can start here in parallel: provider compiler and closed lists, the crate, resident
   modules, routes, CLI, dashboard, discovery namespace and docs (BP-T100 to BP-T155), then the noise
   controls, the fixture origin and the conformance kit (BP-T175 to BP-T182). Use the testkit provider
   in Rust tests and the fixture provider in Gauntlet runs. Add a real provider manifest only from
   that provider's confirmed API contract, and run the conformance kit on it.
8. Phase 2: session store, new grant targets and eligibility, cross-origin rule, durable per-site
   choice, deny memory, evaluation order, coalescing, grant controls, policy scopes, surface
   resolution, routes, Browser area, CLI, invariant regressions, Gauntlet (BP-T040, BP-T060 to
   BP-T078), together with the quiet set, retry attach, prompt accounting, the report path and observe
   mode (BP-T168 to BP-T174). Then wire provider tightening to the new grants (BP-T127).
9. Live cases beyond the browser catalog, and the mining loop: approval round trips, full-task browser
   tasks, installed acceptance rows, the mining tool and the ledger (BP-T183 to BP-T189).
10. Phase 4 only after ADR 0017 is accepted: protocol method table, passthrough resolution, relay
    crate and command behind a flag (BP-T080 to BP-T087).
11. Phase 5: the companion extension ADR (BP-T090).
12. Close-out measurements, release-gate evidence and installed-Guard check (BP-T200 to BP-T207).

Keep pull requests small and single-purpose: one contract, one module set, or one driver profile at a
time. Land the table migration (BP-T013) alone so parity is easy to prove.

## Working rules

- This repository is public. Before every commit message, pull-request title, body, comment or review
  reply, re-read the full outgoing text and remove private hosts, addresses, machine names, local
  paths, usernames, private repository or product names, and pasted logs.
- Fixtures, tests and public text use synthetic names: `example-org`, `shop.example.test`,
  `provider.exampleshield`, `browser.example-pilot`. Do not name a prospective sponsor or copy shapes
  from any private checkout.
- Hosted-service work (placement contract, sponsor entitlement, checkout) is out of scope for this
  repository. Do not describe its internals here. Refer to it as "the hosted Guard service".
- Never approve your own Guard requests. Show the approval link to the user.
- Run focused tests locally. Let CI run the full Python and Rust suites, and fix from its failure list.
- Add each new Rust source file to `rust/build_support/command_source_inputs.v2.json`.
- Add Gauntlet and fixture cases mid-list, not at the end, to avoid merge conflicts.
- When a test from the approval-invariant regression list fails, fix the change. Do not relax the test.
- Every pull request that changes a browser or provider decision ships a Rust test, a benign gate row
  and a live Gauntlet case together. Pick the cheapest layer that fails on the parent commit as the
  primary proof, and still add the others. If the Gauntlet cannot reach the behavior, extend the
  fixture driver or the page model until it can.
- Direction-check every case: it fails on the parent commit and passes on the head. A case that passes
  on both is not a case.
- Never change an oracle, an expectation, a pinned gate row or an `approval_budget` to make a change
  pass. A louder class for an existing row is a product decision, argued in the pull request with the
  protection gap it closes, and added as a new row beside the old one.
- Every protect-class case has a benign counterpart on the same driver and page. Every live
  `browser-quiet` tool call is mirrored in the gate's `mcp_cases`.
- Write case prompts the way a developer would ask for the work. Do not describe the target as a test,
  a fixture, or as disposable, synthetic or authorized. Do not wrap catalog placeholders in quotes.
- The Gauntlet is never a CI job and never a required check. Do not add it to a workflow. Use `--case`
  runs while iterating and never report one as qualification. Do not run full qualification for an
  ordinary pull request. The deterministic gate and the replay lane cover those in CI.
- At release, both existing halves of the gate still apply (core qualification, and the full-task
  discover run with `false-positives.json` triage), and the `browser` and `approval-retry` profiles
  run as a named step. Report a browser budget that did not run as `unmeasured`, never as a pass.
- When you find a browser false positive while working, fix it in its own pull request with the three
  artifacts and add a row to the ledger. Do not fold it into an unrelated change and do not leave it
  as a note.
- Mine real prompts from a copy of the Guard database, never the live file, and never paste a row,
  URL, path or argument from it into a fixture or public text. Rebuild the shape with synthetic names.
- New dependencies need a recorded review (license, size, maintenance, `unsafe`). The relay's
  WebSocket dependency is decided in ADR 0017, not in a pull request.
- Do not regenerate shared catalogs or directory files by hand in a contribution pull request.
  Maintainer artifact regeneration publishes them after merge.

## Decisions already made

Treat these as settled unless an ADR reverses them:

- No provider allow. Tightening only.
- No provider call on the decision path.
- Page content, typed text, cookies, selectors, file names and local identifiers never go to a
  provider.
- Shared-profile drivers get `session-site` grants with the listed exclusions, not full timed grants.
- "Always allow <verb> on <site>" is an added durable choice. The exact-action Always allow is
  unchanged.
- Yanez Pulse keeps its current crate and behavior. Moving it onto the generic crate is a follow-up.
- `publisher.verified` is set by maintainers only, and needs a calibration report.
- Guard is the integration venue. It ships no detection of its own and no code for one named vendor.
- A prompt the user did not need is a defect with the same weight as a missed protection (I14).
- A provider that answers `ok`, `unknown` or nothing adds zero prompts. An unverified provider's
  `caution` is a finding, not a review (I15).
- The caps in PRD 6.12 are constants, not settings.
- Browser MCP cases live in their own harness-only Gauntlet profile. `QUALIFYING_LANE` does not change.
- The first navigation to a new public site is one card with the site grant offered, not quiet.

Open decisions are listed in PRD section 10. Resolve each in the ADR named there or raise it with the
maintainers before building on it.

## Acceptance evidence

Provide a concise report containing:

- changed files grouped by phase and the `BP-T###` items each pull request closes
- focused test commands and exact-head CI run links
- parity proof: the pre-existing browser intent, temporary grant, policy scope and projection vectors
  pass unchanged after the table migration
- approvals per scripted 20-action browser task before and after, per first-party driver
- hook decision latency p50 and p95 before and after, and the proof that the decision path performs no
  provider I/O
- the privacy suite output showing each capability's request equals its declared share set, and that
  excluded origins produce no request
- the secret suite output showing the key never leaves the resident
- the outage suite output showing no decision change beyond the documented tightening
- Gauntlet results by phase: the `browser` profile on Claude Code, Codex and Cursor, the browser cases
  in the core catalog, and the browser additions to the approval-retry catalog, with the lanes that
  ran and the lanes that did not
- the browser budget table with every row `within`: browser false pauses 0, approvals over budget 0,
  repeat prompts 0, provider-added prompts 0, review rows missing a choice 0, failed protection cases
  0, plus approvals per completed task and quiet-case rate per driver id
- the full-task discover run on three harnesses and the triage of each `false-positives.json`, ranked
  by `policy_action`, showing no browser class that is new since the previous release tag
- the no-added-prompt differential and the bounded-prompt check for every shipped provider manifest,
  from `hol-guard integrations conformance`
- the false-positive ledger: every class found, with its fix pull request, gate row id and live case
  id, and the direction check for each case
- the installed-Guard check: Guard version, agent, one driver profile's `browser explain` results, and
  the testkit provider connect flow
- screenshots of the browser approval card, the Browser area and the connect dialog at 320 and 1440
  CSS pixels

The work is ready when a routine 20-action task on one site needs at most one approval under a site
grant, every reference driver's documented tools are mapped or explicitly unclassified, a navigation
to Guard's own origin is blocked, a connected provider's `danger` signal leads the card without
removing either required choice, a provider outage changes no decision, and both rollback switches
restore prior behavior on a released build.

It is also not ready until the quiet side holds: a task on an already granted site and a check of a
local development page need zero approvals, no covered action asks twice, a connected provider that
has nothing bad to say adds no prompt, a second provider adds no second review for the same subject,
every reference driver tool has a pinned gate row with a benign and a protect case, and a new provider
can be added with a manifest, its fixtures and a passing conformance run, with no change to Guard's
Rust.

Do not mark TODO items complete from configuration inspection alone. Each checked item needs merged
code, a test that fails without it, and the evidence the item names.
