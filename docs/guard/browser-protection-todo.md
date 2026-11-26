# Browser Protection and Provider Integrations TODO

This checklist implements [the Browser Protection PRD](./browser-protection-prd.md). Section numbers in
parentheses refer to that document. A checked item requires merged code, tests that fail without the
change, and the evidence named in the item. Configuration inspection alone never checks an item.

Rules that apply to every item:

- New runtime logic is Rust. Python changes are argument parsing, rendering, or a call into the native
  runtime (PRD I5).
- Every new Rust source file is added to `rust/build_support/command_source_inputs.v2.json`.
- Fixtures, tests, commits and pull-request text use synthetic names (`example-org`, `shop.example.test`,
  `provider.exampleshield`). Never a real site, vendor, repository or host.
- A change that touches approval tokens, scope contracts, saved decisions or the review card re-reads
  `docs/guard/approval-invariant.md` first and keeps Allow once and Always allow on every review.
- Source files stay near the 500-line guideline. JSON data files are exempt.
- Run focused tests locally. CI runs the full Python and Rust suites.
- Guard is the venue, not the detector (PRD 1, 6.1). No item adds reputation, script analysis or
  malware logic to this repository. A provider is a manifest, fixtures and a review.
- Every pull request that changes a browser or provider decision ships three artifacts together: a
  Rust test, a row in `tests/fixtures/benign_false_positive_gate.json`, and a live Gauntlet case
  (PRD 8.6). "The Gauntlet cannot reach it" is not an exit. Extend the fixture driver instead.
- Every case is direction-checked: it fails on the parent commit and passes on the head. Say so in the
  pull request.
- Never edit an oracle, an expectation, a pinned gate row or an `approval_budget` to make a change
  pass (PRD I14, R-QUIET-3).
- Every protect-class case has a benign counterpart on the same driver and page.
- The Gauntlet is never a CI job. Use `--case` runs while iterating. They never qualify anything.

Dependencies: phase 0 gates everything. The regression harness section (BP-T160 to BP-T167) lands
before the first phase 1 decision change. Phases 1 and 3 can run in parallel after phase 0. Phase 2
needs phase 1. Phase 4 needs phase 1 and ADR 0017. Phase 5 is planning only.

## Phase 0: decisions, contracts, switches

- [x] **BP-T001** Write `docs/guard/adr/0018-provider-integration-authority.md`. Record: signals are
  evidence (I2), tightening-only composition (I3), payment independence (I4), fail direction (I10),
  the closed capability and fact lists (6.3, 6.4), and decisions D1, D2, D4. Evidence: ADR merged.
- [ ] **BP-T002** Write `docs/guard/adr/0017-browser-cdp-relay.md` as a design-gate ADR. Record: the
  relay threat model, the WebSocket dependency options with license, size, maintenance and `unsafe`
  review, the sync-versus-async decision (D3), bounds, and the fail-closed rule (5.6). Evidence: ADR
  merged with an explicit accept or defer decision. No relay code before it is accepted.
- [ ] **BP-T003** Add `rust/crates/guard-contracts/src/browser_action.rs` with `BrowserActionV2`,
  `BrowserVerbV1`, `BrowserTargetV2`, `BrowserElementV1`, `BrowserInputV1`, `BrowserCardV1` (5.1, 5.8).
  Serde round-trip and `deny_unknown_fields` tests. Keep `BrowserAutomationIntentV1` readable.
- [ ] **BP-T004** Add `rust/crates/guard-contracts/src/provider_signal.rs` (`ProviderSignalV1`,
  verdict, state, subject, capability enums) and `provider_integration.rs` (route wire types, 6.9).
  Round-trip tests. No secret-bearing field implements `Debug` or `Serialize` outward.
- [ ] **BP-T005** Add schemas `contracts/browser-drivers/driver.v1.schema.json` and
  `contracts/provider-integrations/provider.v1.schema.json`. Add schema tests under `tests/` that
  accept the synthetic examples from PRD 5.2 and 6.2 and reject: regex in `match`, a reserved generic
  name, a wildcard host, an IP literal host, a non-443 port, a query-string credential, a `shares` list
  that differs from the facts used, a remote icon URL, and limits above the Guard caps.
- [ ] **BP-T006** Create `contributions/browser-drivers/` and `contributions/provider-integrations/`
  with a `README.md` each. Extend `scripts/refresh_extension_artifacts.py` (`--trust-only`,
  `--check-trust`) to enumerate both directories and create
  `contracts/extensions/trust/browser.<slug>.v1.json` and `provider.<slug>.v1.json` bindings as
  external and opt-in. Extend the packaged-contract copy and Hatch force-include so both directories
  ship in the wheel. Evidence: trust check green, wheel contents test.
- [ ] **BP-T007** Add rollback switches: `HOL_GUARD_BROWSER_PROTECTION=legacy` (classification falls
  back to the pre-change tables and grants) and `HOL_GUARD_PROVIDER_INTEGRATIONS=off` (routes answer
  `provider_capability_unavailable`, decide step is a no-op). Model both on `HOL_GUARD_DISCOVERY=off`
  in `rust/crates/guard-runtime/src/daemon_edge_discovery.rs`. Tests prove each switch.
- [ ] **BP-T008** Record the baseline: count approvals for a scripted 20-action browser task on one
  site with each first-party driver on current main, and the p50 and p95 hook latency of a browser MCP
  tool decision. Store the numbers in the pull request that lands BP-T003.
- [x] **BP-T009** Record in ADR 0018: I14 and I15, the three prompt classes (5.10), the provider
  effect levels and caps (6.12), and decisions D10 to D16. Evidence: ADR merged.

## Regression harness and false-positive control

This section implements PRD 5.10, 6.12 and 8.2 to 8.7. Read `ci/gauntlet/README.md` before starting.
Phase tags say when an item can land. Harness items come first so that every later pull request has a
place to put its cases.

### Harness (phase 1, before any decision change)

- [ ] **BP-T160** Fixture driver in `ci/gauntlet/browser_fixtures.py`, following
  `ci/gauntlet/connector_fixtures.py` (PRD 8.3). A stdio MCP server installed under the server name
  and launch shape of one reference driver, serving the tool list recorded in
  `tests/fixtures/browser_drivers/<slug>/tools.json`. Scripted page model with named pages
  (`shop-basket`, `shop-login`, `docs-article`, `partner-landing`, `local-dev`): origin, elements, a
  form, a password field, a file input, a download link, an outbound link. No browser, no socket.
  Journal every executed call to `output/browser-calls.jsonl`. Evidence: unit tests for the page
  model and the journal.
- [ ] **BP-T161** Second driver stand-in under a name no profile matches, with two routine tools, and a
  recording `chromium` stand-in on `PATH` that logs argv and exits. Evidence: unit tests.
- [ ] **BP-T162** Baseline gate rows. Before any classification change, add `mcp_cases` rows for every
  tool of the first-party drivers with the decision current main gives, in their own pull request.
  Later pull requests then show every class change as a diff. Extend
  `tests/benign_fp_gate_mcp.py` (or add `tests/benign_fp_gate_browser.py`) to install the fixture
  driver and replay through the native stdio relay. Add the optional row fields `state` and `page` as
  closed lists, with the presets from PRD 8.2, and the extra assertions for `allow` (no row, no
  rendered text) and `review` (both choices, exact-action token, eligible grant). Evidence: the gate
  runner rejects an unknown preset; rows green on main.
- [ ] **BP-T163** Replay lane: record the browser hook payload each harness sends (`claude-code`,
  `codex`, `cursor`, `zcode`, `omp`, `pi`) and add anonymized rows to
  `tests/fixtures/gauntlet_replay_cases.json` with `quiet`, `always` and `block` expectations.
  Evidence: `tests/test_guard_gauntlet_replay_gate.py` green; one row per harness per class.
- [ ] **BP-T164** `browser` Gauntlet profile (PRD 8.4). `ci/gauntlet/lane_coverage.py`: add `"browser"`
  to `PROFILES` and `_HARNESS_ONLY_PROFILES`. `ci/gauntlet/catalog.py`: add oracles `browser-quiet`,
  `browser-task`, `browser-blocked`, fields `browser_fixture`, `provider_script`, `approval_budget`
  (0 to 4), and refuse them in the `core` profile. Create `ci/gauntlet/browser.json` and
  `ci/gauntlet/browser_judge.py` (approval-row count, rendered-card count, journal check,
  `decision_paths`). Evidence: catalog tests for each new field and each refusal; judge unit tests
  for pass, over budget, repeat prompt, protected call present, attempt never made.
- [ ] **BP-T165** Pairing and coverage tests: `tests/test_gauntlet_browser_cases_in_fp_gate.py`
  (every `browser-quiet` tool call appears in `mcp_cases` as `allow`, modeled on
  `tests/test_gauntlet_native_commands_in_fp_gate.py`) and
  `tests/test_browser_driver_gate_coverage.py` (every tool of every shipped profile has a pinned row;
  every mapped verb class has an `allow` row under a grant and a `not_allow` row; every shipped
  provider manifest has a row per verdict and failure state; every protect row has a benign pair).
- [ ] **BP-T166** Browser rows in `ci/gauntlet/release_budgets.py` (PRD 8.5): browser false pauses,
  approvals over budget, repeat prompts, provider-added prompts, review rows missing a choice, failed
  browser protection cases. Each reports `within`, `over` or `unmeasured` in `summary.json` and
  `qualification.json`, plus approvals per completed task and quiet-case rate per driver id.
  Evidence: unit tests with synthetic case results for each state.
- [x] **BP-T167** Document the profile, oracles, fields, fixtures, budgets and the release-time step in
  `ci/gauntlet/README.md`. Add a **Regression cases** section (gate row ids, live case ids, direction
  check) to the browser driver and provider integration pull-request templates.

### Quiet by default (phase 2)

- [ ] **BP-T168** Quiet set for loopback development origins (PRD 5.10, D10) as a pure Rust function
  beside the grant evaluation, with the exclusions: Guard's own origin, `LOCAL_ADMIN_PORTS`, recorded
  debugging ports, sensitive surfaces, `shared` and `remote-debugging` profiles. Vectors for each
  exclusion. Gate rows: local page click `allow`, same click on an admin port `not_allow`, same click
  in a shared profile `review`. Live: `browser-quiet-local-dev-page`.
- [ ] **BP-T169** R-QUIET-1: a retried call attaches to its pending row, and an action covered by a
  live grant, saved allow or answered row never creates a row. Store test, gate preset
  `pending-same-call`, live case `browser-task-retry-while-pending`.
- [ ] **BP-T170** R-QUIET-2: unknown tools on one driver in one session coalesce into one card that
  lists them. Live case `browser-task-unknown-tools` with budget 1.
- [ ] **BP-T171** `browser_prompt_stats` table in the native store (digests and counts only), written
  when a browser review is raised and when it is answered. Browser area shows the per-site count and
  offers the covering grant as a suggestion. Tests: no URL, path or argument text in any row; no
  route exports the table off the device; the suggestion never creates a grant without the proof
  flow.
- [ ] **BP-T172** Report path: card menu item "This should not have asked" and
  `hol-guard browser report-prompt <request-id>`, native. Output is the anonymized skeleton from PRD
  5.10. Test: every argument value is a placeholder and the origin is `site-a.example.test`.
- [ ] **BP-T173** R-QUIET-4: `observe` state for an external driver profile mapping. The decision is
  unchanged and a would-have-stopped receipt is written in the Watch format. First-party floors and
  native sensitive-surface screens ignore it. Vectors both ways.
- [ ] **BP-T174** Extend the drift check (BP-T027) to open one issue listing new upstream tools per
  driver with a generated profile patch and its gate rows (R-QUIET-5).

### Provider noise control (phase 3)

- [ ] **BP-T175** Effect level per provider and capability (`observe`, `tighten`, `enforce`) as a
  protected setting through the settings route (preview plus proof) and managed policy. Default
  `tighten`. `enforce` is the existing "Enforce provider blocks". Extends BP-T125.
- [ ] **BP-T176** `rust/crates/guard-provider-integrations/src/noise.rs`: unverified `caution` is a
  finding only; one provider-caused review per subject per signal version; three per session per
  provider, then findings plus one Browser-area notice; `danger` uncapped; a review Guard raises
  anyway is not counted. Property test: for any signal sequence the number of provider-caused reviews
  never exceeds the caps, and no sequence produces an allow Guard would not have given.
- [ ] **BP-T177** Override accounting: after three allow-throughs of the same provider and reason code
  in seven days the card offers "Stop asking for this reason from <provider>". Accepting sets that
  reason code to `observe`. Integrations page lists each with undo. Tests: never automatic, never
  below Guard's own decision, undo restores.
- [ ] **BP-T178** Multi-provider composition: strongest fresh verdict per subject, one review per
  subject, rows sorted by verdict then provider id, three rows plus "N more", placement never orders.
  Vectors and a Playwright spec for the card with four providers.
- [ ] **BP-T179** `fixture_origin.rs` and the loopback provider stub (PRD 8.3).
  `HOL_GUARD_PROVIDER_FIXTURE_ORIGIN`, modeled on `HOL_GUARD_DISCOVERY_FIXTURE_ORIGIN`. One Rust test
  per restriction: loopback only; `provider.fixture-` ids only; the compiler rejects that prefix under
  `contributions/`; only the literal fixture key is ever sent; a stored secret is never sent; the
  Integrations page marks the provider as a fixture. Stub in `ci/gauntlet/browser_fixtures.py` with
  per-case scripts and a request journal.
- [ ] **BP-T180** Conformance kit: `conformance.rs` and `hol-guard integrations conformance
  <manifest>` (PRD 6.12), runnable from the released CLI. Five checks: compile and labels, recorded
  responses, share set, no added prompt, bounded prompt. CI runs it for every manifest under
  `contributions/provider-integrations/`. Add `hol-guard extensions generate --provider` and
  `validate --provider` so a manifest is generated with its fixtures and gate rows.
- [ ] **BP-T181** Calibration for `verified` (D12): document the report format, the public list named
  by digest and the starting thresholds in the provider contributing guide. No list is checked in.
- [ ] **BP-T182** Noise view on the provider detail page and in `hol-guard integrations status <id>`:
  reviews caused in seven days, allowed through, quieted reason codes, effect level per capability.

### Live cases beyond the browser catalog

- [ ] **BP-T183** `approval_retry.json` browser additions (PRD 8.4), answered by
  `approval_retry.ReviewApprover`: Allow once then retry; Always allow exact then repeat with no
  card; one-hour site grant then three actions with no card; session-site in a shared profile; block
  site then a stopped second attempt with no new card; `danger` on a saved Always allow shown as
  paused and still approvable; one relayed approval link for a browser card.
- [ ] **BP-T184** Two quiet-class tasks in `full_tasks.json` that include a browser check of a local
  page, run in discover mode on Oh My Pi, Claude Code and Codex. Evidence: no browser entry in any
  lane's `false-positives.json`.
- [ ] **BP-T185** Include the browser replay rows in `python -m ci.gauntlet installed` so installed
  acceptance covers them.
- [ ] **BP-T186** Optional real-browser lane in the full-task container: a real reference driver, a
  headless browser, the gateway serving the synthetic sites. Never gating. Evidence: one recorded run
  and a note of every difference from the stand-in.

### Mining and release

- [ ] **BP-T187** Mining tool under `scripts/` that reads a copy of the Guard database, groups browser
  approval rows by driver id, verb and reason code, joins `browser_prompt_stats`, and prints
  candidate classes (allowed every time). It never opens the live file and prints no URL or argument
  text.
- [ ] **BP-T188** False-positive ledger in the tracking issue: class, reason code, driver, fix pull
  request, gate row id, live case id. Run BP-T187 before each release and after each new reference
  driver. A class without all three ids is open.
- [ ] **BP-T189** Release checklist entry: run the `browser` and `approval-retry` profiles on Claude
  Code, Codex and Cursor from the exact-source wheels, read every lane's `false-positives.json`
  ranked by `policy_action`, and put the browser budget table and the list of lanes run and not run
  in the release report. A new browser class since the previous tag is fixed first.

## Phase 1: classification at every entry point

### Driver profiles

- [ ] **BP-T010** Add `rust/crates/guard-command/src/browser_driver_compile.rs`: parse and validate
  `guard.browser-driver.v1`, enforce every constraint in PRD 5.2, emit a compiled table. Wire it into
  `scripts/build_native_command_program.py` and the native catalog build. Unit tests per rejection.
- [ ] **BP-T011** Add `rust/crates/guard-command/src/browser_driver_match.rs`: resolve a tool call to
  a driver by MCP server name, package, tool namespace, or harness tool name. First-party beats
  external, exact beats namespace, and two external profiles claiming one identity is a compile error.
- [ ] **BP-T012** Add the verb-to-intent table and `BrowserActionV2` projection in
  `rust/crates/guard-command/src/browser_action_project.rs`, including discriminator tools (`action`
  argument) and `cdpPassthrough` tools (resolved by BP-T080 when present, `Other` until then).
- [ ] **BP-T013** Move `CHROME_DEVTOOLS_*` and `PLAYWRIGHT_*` tables and the profile flag lists out of
  `browser_mcp_patterns.rs` into `contributions/browser-drivers/browser.chrome-devtools-mcp.json` and
  `browser.playwright-mcp.json` (trust class first-party). Keep the generic regex fallback native.
  Evidence: `tests/test_guard_browser_mcp_intent.py`,
  `tests/fixtures/mcp_tool_policy/parity_vectors.json` and
  `tests/fixtures/mcp_proxy_decision/call_projection_vectors.json` pass unchanged.
- [ ] **BP-T014** Keep native sensitive-surface screens authoritative: run `visit_sensitive_surfaces`
  and the `SENSITIVE_*` patterns on every browser call after profile projection and union the result.
  Test: a profile that labels a script-evaluating tool `Read` still yields `script_eval` and
  `browser.privileged`.
- [ ] **BP-T015** Unlisted tool on a matched driver is `unclassified`: normal MCP review, no grant
  eligibility, card says Guard does not know this tool. Test.
- [ ] **BP-T016** External profiles are inert until a local-admin enable; signed-cloud enable cannot
  turn one on; a this-device custom MCP grant still wins. Mirror the tests in
  `tests/test_guard_mcp_server_contribution.py`.

### Reference driver set

Each item: profile JSON, trust binding, portable vectors under `tests/fixtures/browser_drivers/`, the
upstream version and tool-list URL recorded in `referenceUrls`, and one `hol-guard browser explain`
transcript in the pull request (after BP-T052).

- [ ] **BP-T020** Puppeteer-style DevTools MCP servers.
- [ ] **BP-T021** Extension-bridge browser tools that arrive under an `mcp__<name>__` namespace and act
  in the user's signed-in browser. Default `profile_mode: shared`.
- [ ] **BP-T022** Screen and computer-use tools with an `action` discriminator. Default
  `profile_mode: shared`. Map screenshot, pointer, keyboard and scroll actions; anything else `Other`.
- [ ] **BP-T023** Agent browser frameworks with natural-language `act`, `extract`, `observe` tools. A
  free-text instruction tool is `Other` unless the tool also supplies a structured action.
- [ ] **BP-T024** Hosted browser services: session create, connect, live-view tools.
  `profile_mode: remote-debugging`.
- [ ] **BP-T025** Harness built-ins. Route `browser`, `browser_action`, `open_url`, `visit_url` from
  `rust/crates/guard-hook-payload/src/hook_adapter_cline_tables.rs` (`NETWORK_TOOLS`) and
  `rust/crates/guard-command/src/adapters/hook/hook_adapter_envelope_tables.rs`
  (`CURSOR_NETWORK_TOOL_NAMES`, `CURSOR_NETWORK_URL_KEYS`) through the driver matcher so they produce a
  `BrowserActionV2`. When a known browser built-in matches no profile, or its payload shape changed,
  produce an unclassified `BrowserActionV2` (verb `Other`, reviewed) so the Guard-origin block and the
  browser sensitive-surface screens still run, and keep the network-request facts as extra evidence
  rather than as the only classification. Hook payload parity tests for each affected harness, including
  an unmatched tool and a changed payload shape.
- [ ] **BP-T026** Oh My Pi eval facade: make `generic_omp_eval_browser.rs` and its `_flow`, `_lex`,
  `_page` modules emit a `BrowserActionV2` for both admitted and reviewed shapes. Admission rules do
  not change. Existing `generic_omp_eval_browser_tests.rs` stay green.
- [ ] **BP-T027** Add a scheduled drift check (`scripts/` plus a workflow) that compares each
  first-party profile's recorded upstream version with the latest published one and opens a report.
  Report only; it never edits a profile.

### Launch layer

- [ ] **BP-T030** Add `contributions/command-sources/command.browser-automation.json` with the rules
  in PRD 5.3 using existing native operations only, plus its listing under
  `contributions/extension-listings/` and trust binding. Fixtures:
  `tests/fixtures/command-source-browser-automation.v1.json` covering remote-debugging launch,
  real-profile launch, WebDriver server, automation CLI, and the safe headless temporary-profile
  variant, on POSIX and Windows command shapes.
- [ ] **BP-T031** Run `hol-guard command explain` on one destructive and one safe case and complete the
  **Installed Guard check** section of the command extension pull-request template.
- [ ] **BP-T032** Session-scoped debugging ports: when a reviewed launch names a remote debugging
  port, record it on the browser session (BP-T040) and treat a loopback request to that port like the
  entries in `LOCAL_ADMIN_PORTS` (`rust/crates/guard-command/src/pretool/curl_reads.rs`,
  `loopback_ports.rs`). Test both the recorded-port and the unrecorded-port case.
- [ ] **BP-T033** Move MCP launch `profile_mode` flag lists into driver profiles and keep the generic
  flags (`REMOTE_DEBUG_FLAGS`, `PROFILE_DIR_FLAGS`, `ISOLATED_FLAGS`) as the native fallback.

### Self-protection

- [ ] **BP-T035** R-SELF: compute `target.is_guard_origin` from the daemon port and state. A browser
  action on it is `block` with risk category `browser_guard_origin`. Add the category to `NAMES` in
  `rust/crates/guard-command/src/mcp_tool_risk.rs` with a display string in `mcp_tool_signals.rs`, and
  to `HARD_RISK_EXCLUSIONS` in `rust/crates/guard-runtime/src/temporary_mcp_grant.rs`. No grant,
  saved approval or contributed default overrides it. Tests: `localhost`, `127.0.0.1`, `[::1]`,
  decimal and hex host encodings, trailing dot, and a redirect target.
- [ ] **BP-T036** Add the dashboard copy for the R-SELF block and the agent-facing reason text. The
  text must not contain the approval URL.

### Native card projection

- [ ] **BP-T045** Extend the `Display` branch of `evaluate_browser_mcp` in
  `rust/crates/guard-command/src/browser_mcp_intent.rs` to return `BrowserCardV1`: headline parts,
  site line, browser line, element and input preview, risk chips, grant options. Input preview class
  comes from the native secret scanner. Typed text is never persisted. Vectors under
  `tests/fixtures/browser_drivers/card_vectors.json`.
- [ ] **BP-T046** Dashboard reads `BrowserCardV1`. Delete the name-based inference in
  `dashboard/src/mcp-call/browser-tools.ts` and `ROUTINE_BROWSER_OPERATIONS` in
  `dashboard/src/temporary-mcp-approval.ts`. Update `explain-mcp-call.ts`, `mcp-call-card.tsx`,
  `mcp-brand.ts`, and the tests `explain-mcp-call.test.tsx`, `mcp-call-ux.test.tsx`. A card with no
  native projection falls back to the generic MCP card, never to a guess.
- [ ] **BP-T047** Build the card anatomy from PRD 5.8 items 1 to 5 and 7 in a new
  `dashboard/src/browser-call/` module set (card, site line, browser line, input preview, risk chips).
  Allow once and Always allow remain the two primary cards (`mcp-decision-choice.tsx`). Deny is always
  visible.
- [ ] **BP-T048** Playwright spec `dashboard/e2e/browser-approval-card.spec.ts` at 320, 390, 720, 800,
  1024 and 1440 CSS pixels: no horizontal overflow, keyboard-only operation, accessible names on every
  chip and choice.

### Catalog surface

- [ ] **BP-T050** Add `surfaces` and the kinds `browser` and `provider` to catalog v2 generation and
  the native catalog read model (ADR 0014). Derivation per PRD 5.9. Regenerate
  `docs/guard/extensions/catalog.v2.json` through the maintainer flow only.
- [ ] **BP-T051** Add listing category `browser-web` to
  `contracts/extensions/listing.v2.schema.json`,
  `src/codex_plugin_scanner/guard/extension_builder/listing.py` and
  `scripts/notify_merged_extension_claimants.py`. Add the surface filter to Protection Center
  (`dashboard/src/protection-center/`).
- [ ] **BP-T052** CLI `hol-guard browser explain --driver <id> --tool <name> --args <json>`: native,
  side-effect free, prints the `BrowserActionV2`, the decision, and grant eligibility. Python is
  argument parsing and rendering.
- [ ] **BP-T053** Extension Builder: `hol-guard extensions generate --browser` and
  `validate --browser`. Document in `docs/guard/extension-builder/README.md`.
- [ ] **BP-T054** Write `docs/guard/extensions/browser-driver-contributing.md`, add a browser driver
  pull-request template section with an Installed Guard check, and add a "Browser driver
  contributions" section to `AGENTS.md`.

### Phase 1 qualification

- [ ] **BP-T058** Gauntlet phase 1 cases (needs BP-T160 to BP-T166). In `ci/gauntlet/browser.json`:
  `browser-quiet-read-only-tools`, `browser-task-unknown-tools`, `browser-blocked-cookie-read`,
  `browser-blocked-script-evaluation`, `browser-blocked-upload`, `browser-blocked-password-field`,
  `browser-blocked-guard-origin`, `browser-blocked-debug-port`. In `ci/gauntlet/scenarios.json`,
  added mid-list and mirrored verbatim in the benign gate: safe headless temporary-profile launch
  allowed, remote-debugging launch on the default profile stopped, Oh My Pi eval loopback page quiet,
  Oh My Pi eval cookie read stopped. Each protect case declares `decision_paths`. Evidence: direction
  check for each case, and one run of the `browser` profile on Claude Code, Codex and Cursor with
  zero browser false pauses.
- [ ] **BP-T057** Gate coverage for the reference driver set: BP-T165 green for every profile added
  in BP-T020 to BP-T026, with rows generated by `extensions generate --browser` (BP-T053). The
  generator emits the rows and `validate --browser` fails without the benign pair.
- [ ] **BP-T059** Extend `scripts/native_slo_contract.py` with the browser decision path. Evidence:
  p95 within 5 ms of the BP-T008 baseline.

## Phase 2: sessions, sites, grants

- [ ] **BP-T040** Browser session model: `browser_sessions` table through the native `ensure_schema`
  chain, with session digest, harness, driver identity hash, profile mode, first and last seen, known
  debugging ports, current origin. Module `rust/crates/guard-runtime/src/browser_session_store.rs`.
  Sessions expire with the harness session or after an idle bound.
- [ ] **BP-T060** Add targets `site-category`, `site`, `site-group`, `session-site` and duration
  `session` to `rust/crates/guard-runtime/src/temporary_mcp_grant.rs` with the selectors in PRD 5.5.
  Extend `guard_store_temporary_mcp.rs` (`covers`, `covered_request_ids`, `resolve_covered`) with
  target kind and digests. Existing `exact`, `category`, `server` selectors keep working for stored
  rows. Compute `driver_identity_hash` as PRD section 3 defines it. Tests: a second profiled tool of the
  same driver on the same site is covered, an unprofiled tool of the same driver is not, and a changed
  tool schema ends the grant.
- [ ] **BP-T061** Eligibility rules: `site*` targets keep today's routine-only rule and hard
  exclusions. `session-site` is eligible when the only excluded risk is `browser_shared_profile`, and
  never covers transfer, privileged, a sensitive surface, a password or payment element, or a
  `looks_like_secret` input. Table-driven tests for every combination.
- [ ] **BP-T062** Cross-origin rule: a grant never follows a navigation to another origin. The first
  action on the new origin is reviewed with a "left the granted site" marker. Navigations and other
  URL-bearing calls are decided on their destination before they run, and a command with no known
  origin (navigation in flight, unknown frame) is reviewed. Test redirects, `window.open` style new
  tabs, cross-origin frames, and a command sent during a pending navigation.
- [ ] **BP-T063** Durable "Always allow <verb> on <site>": saved allow on
  `{intent, verb, target_origin, profile_mode, driver_identity_hash, sensitive_surface_flags: []}`
  with no argument hash, offered only for routine categories with an empty surface set. Wire through
  `mcp_tool_policy_grants.rs`, `approval_scope_contract.rs` and the saved-decision readers listed in
  the enforcement table of `docs/guard/approval-invariant.md`. The exact-action Always allow is
  unchanged. Update that document's "Scope choices" and regression-test list.
- [ ] **BP-T064** Deny memory: `mcp_grant_target` values `deny-site` and `deny-site-group` with
  durations `session` and `always`. Checked after R-SELF and before any grant. Agent sees a block with
  a clear reason. Removal is a protected settings mutation.
- [ ] **BP-T065** Evaluation order per PRD 5.5 in `mcp_tool_policy_flow.rs`. Update the list in
  `docs/guard/mcp-server-contributions.md`. Add an ordering test with every tier present.
- [ ] **BP-T066** Burst coalescing: pending browser rows from one session on one origin within the
  review window render as one card with a count and a step list; resolving with a grant resolves
  covered rows and leaves uncovered rows pending. Queue grouping in `dashboard/src/queue-state.ts` and
  `review-queue-item.tsx`.
- [ ] **BP-T067** Dashboard grant controls: extend `dashboard/src/temporary-mcp-approval.ts`,
  `temporary-mcp-approval-controls.tsx` and `buildTemporaryMcpResolutionFields` for the new targets and
  durations, driven by the native options. Default preselection `site-category` for 15 minutes when
  eligible. "Block on this site" under More choices.
- [ ] **BP-T068** Public-suffix snapshot for `site-group` in `guard-command-catalog-data` with a
  refresh script and a pinned digest (D5). Until it lands, `site-group` is not offered.
- [ ] **BP-T069** Policy bundle: add `browserVerb`, `siteGroup`, `browserDriver` to
  `BROWSER_SCOPE_KEYS` in `rust/crates/guard-policy-bundle/src/policy_bundle_v1_rules.rs`, update
  `spec/guard-policy/v1alpha1/schema.json`, `docs/policy/schema-reference.md`, and
  `tests/test_guard_policy_bundle_browser_scopes.py`.
- [ ] **BP-T070** R-SURFACE: surface resolution in the resident beside `approval_surface_policy`. For
  `shared` and `remote-debugging` sessions never auto-open a browser approval page; show the request
  on every non-browser surface and print the link for the user. Extend
  `approval_browser_policy_tests.rs`. Update `docs/guard/approval-browser-policy.md`.
- [ ] **BP-T071** R-GATE: setup prompt on the browser card when a shared or remote-debugging session
  has no approval gate. The two required choices stay.
- [ ] **BP-T072** Agent-facing hook text for browser holds and denials: names the site and the wait,
  tells the agent not to retry in a loop, omits the approval link for shared profiles.
- [ ] **BP-T073** Daemon routes `/v1/browser/sessions`, `/v1/browser/sites`, `/v1/browser/grants` in
  `daemon_route_paths.rs` and `daemon_edge_route_calls.rs`, with preview plus one-use proof on every
  mutation.
- [ ] **BP-T074** Protection Center Browser area at `/extensions/browser`: sessions and posture, sites
  with allow, ask, block and revoke, live grants with remaining time, installed drivers, connected
  providers. Simple, Advanced, Developer densities. Playwright spec at the contract widths.
- [ ] **BP-T075** CLI `hol-guard browser status`, `sites list|allow|block|forget`,
  `grants list|revoke`.
- [ ] **BP-T076** Approval-invariant regression additions: every browser review offers both choices
  under every grant target; `session-site` never suppresses them; R-SELF is a block and not a review.
  Extend `ci/gauntlet/approval_retry.json` (BP-T183) and `dashboard/e2e/approval-scope-ui.spec.ts`.
- [ ] **BP-T077** Gauntlet phase 2 cases in `ci/gauntlet/browser.json`:
  `browser-quiet-granted-site-form`, `browser-quiet-saved-verb-site`, `browser-quiet-local-dev-page`,
  `browser-task-single-site` (budget 1), `browser-task-two-sites` (budget 2),
  `browser-task-shared-profile` (budget 1), `browser-task-retry-while-pending` (budget 1),
  `browser-blocked-cross-origin-under-grant`, `browser-blocked-remembered-site`. Each quiet case has
  its `mcp_cases` twin. Evidence: every `browser-task` case inside its budget on three harnesses,
  repeat prompts 0, browser false pauses 0, no failed protect case.
- [ ] **BP-T078** Write `docs/guard/browser-protection.md` (user-facing) and update
  `docs/guard/extension-control-center.md` routes.

## Phase 3: provider integrations

### Contract and compiler

- [ ] **BP-T100** Add `rust/crates/guard-command/src/provider_integration_compile.rs`: validate
  `guard.provider-integration.v1` per PRD 6.2, including exact-host rules, single credential header,
  fact-only request bodies, pointer-only response mapping, `shares` equality, limit caps, safe-text
  labels for reason codes. Unit test per rejection.
- [ ] **BP-T101** Closed capability list and closed fact list in `guard-contracts` (6.3, 6.4), with
  the never-shareable set asserted by a test that enumerates `BrowserActionV2` fields and fails when a
  new field is not classified as shareable or not.
- [ ] **BP-T102** Origin exclusion: loopback, private ranges, link-local, `.local`, `.internal`,
  `.test`, single-label hosts and IP literals never leave the device. Table-driven tests.
- [ ] **BP-T103** Ship the synthetic reference manifest `provider.exampleshield` as a test fixture
  under `tests/fixtures/provider_integrations/` only. Do not add any real provider manifest in this
  phase without that provider's confirmed API contract.

### Crate

- [ ] **BP-T110** Create `rust/crates/guard-provider-integrations` (`client.rs`, `render.rs`,
  `parse.rs`, `lib.rs`, `testkit.rs` behind the `testkit` feature). Pin `ureq`, `zeroize` and TLS
  features to match `rust/crates/guard-yanez-pulse/Cargo.toml`. Add it to the workspace, the build
  manifests and the supply-chain allow lists.
- [ ] **BP-T111** Client rules: HTTPS only, host pin checked before connect, no redirects, capped
  body, connect, read and wall-clock deadlines, managed network policy through
  `guard_command::egress_caller` (`ManagedEgressPolicy::resolve`, `policy_send`). Tests against the
  testkit server: redirect refused, wrong host refused, oversize body, slow body, TLS failure,
  managed-policy refusal.
- [ ] **BP-T112** Strict JSON parse and pointer mapping. Lift `strict_json.rs` from
  `guard-yanez-pulse` into a shared location only if Pulse behavior and tests stay byte-identical;
  otherwise copy with attribution in a comment. Unknown verdict values map to `unknown`; undeclared
  reason codes are dropped; at most eight are kept.
- [ ] **BP-T113** Adapter registry: closed adapter ids for protocols that are not expressible as data.
  Empty in this phase. Document the review bar.

### Resident

- [ ] **BP-T120** `provider_integration_secret.rs`: secret id `provider:<id>:api-key` in
  `encrypted_secret_store`, format validation from the manifest before storing, `Zeroizing` copies
  only. Secret tests: the key never appears in a route response, a log line, a receipt, a store row
  outside the secret store, a panic message or `Debug` output.
- [ ] **BP-T121** `provider_integration_store.rs`: connection rows and the `provider_signals` cache
  table keyed by `(provider_id, capability, subject_digest)`, through the native `ensure_schema`
  chain. Subjects are stored as digests.
- [ ] **BP-T122** `provider_integration_worker.rs`: the only caller of the client. Token bucket,
  negative cache (60 s), jittered refresh, circuit breaker (five failures, 5 minutes), `401` and `403`
  to `key_invalid` with calls stopped.
- [ ] **BP-T123** `provider_integration_decide.rs`: cache read only, applies PRD 6.6. Property test:
  for any signal set the decision is never weaker than the decision with no provider.
- [ ] **BP-T124** Hot path proof: a test that fails if the hook or relay decision path performs
  network I/O or waits on the worker. Latency evidence in `scripts/native_slo_contract.py`.
- [ ] **BP-T125** Settings "Enforce provider blocks" and "Require a fresh check", per provider and
  capability, off by default, protected mutation, settable by managed policy
  (`managed_policy_floor.rs`), never settable by a provider.
- [ ] **BP-T126** Saved approval interaction: a `danger` signal reviews again and shows the saved
  approval as paused; it does not delete it. With enforcement on, the block wins. Tests for both.
- [ ] **BP-T127** Grant interaction: `caution` from a verified provider reviews once per subject inside
  the caps of BP-T176, and is a finding only from any other provider; `danger` suspends grants for
  that subject while fresh. Needs BP-T060; until then the decide step applies to exact and category
  grants.
- [ ] **BP-T128** Lifecycle: disconnect deletes secret and cached signals; uninstall and
  forget-device flows delete all provider secrets. Tests.

### Routes, CLI, dashboard

- [ ] **BP-T130** Routes from PRD 6.9 in `daemon_route_paths.rs`, `daemon_edge_route_calls.rs` and a
  new `daemon_edge_integrations.rs`: header token plus dashboard session, hosted dashboard origins
  refused, preview plus one-use proof on connect, settings and disconnect, rate limit on test.
  Contract tests for every error code.
- [ ] **BP-T131** CLI `hol-guard integrations list|status|connect|disconnect|test|settings`. The key is
  read from a prompt or stdin, never an argument, never echoed. Python is glue only, modeled on
  `cli/approval_pulse_commands.py` and `cli/approval_pulse_parser.py`.
- [ ] **BP-T132** Integrations page `/extensions/integrations` and provider detail
  `/extensions/provider.<slug>`: capability text, "What leaves this device" rendered from `shares`,
  privacy and terms links, publisher verification state, Connect.
- [ ] **BP-T133** Connect dialog modeled on `dashboard/src/pulse-setup-modal.tsx` and
  `pulse-connect-step.tsx`: write-only key field, per-fact toggles, one-use proof, verify, state
  display. "Get a key" link with a static referral parameter and no user data.
- [ ] **BP-T134** Card finding row (PRD 6.8): provider name, capability label, verdict chip, up to
  three reason labels, age. Never reorders or restyles Guard's own findings. Subscribes to a late
  signal on an open card.
- [ ] **BP-T135** Playwright specs for the Integrations page, the connect dialog and the finding row
  at the contract widths, with the testkit provider.

### Sponsors and discovery

- [ ] **BP-T140** Discovery v2 (PRD 6.10). Released runtimes reject the whole snapshot when one
  placement id is outside `command.` and `mcp.` (`is_extension_id` in
  `rust/crates/guard-runtime/src/discovery_placement_op.rs`), so the v1 read must never carry a new
  namespace. Add the `v2` path family in `daemon_edge_discovery.rs` and snapshot schema
  `guard.extensions.discovery.v2` in the projector: accept `browser.` and `provider.`, and drop a
  placement with an unknown namespace instead of failing the snapshot. Keep every other bound (19
  placements, 30 s lease, 64 KiB, 2 s deadline, opt-out, rollback switch, fixture origin). Tests: v2
  accepts the new namespaces, v2 drops an unknown one and keeps the rest, v1 vectors unchanged. Ship
  the runtime change before the hosted service serves any v2 placement.
- [ ] **BP-T141** Render `provider.` placements in the spotlight shelf
  (`dashboard/src/protection-center/extensions-spotlight-model.ts`, `extensions-spotlight.tsx`,
  `extensions-discover-model.ts`) and on the Integrations page with the existing sponsored label. A
  placement never enables or connects anything. Test.
- [ ] **BP-T142** "Sponsor" label on the card finding row only while a live validated placement
  exists for that provider id. No manifest field carries it. Test with discovery off: no label, no
  behavior change.
- [ ] **BP-T143** Update the sponsor statement in `README.md` and
  `docs/guard/yanez-pulse-approval-gate.md` per PRD 6.10.
- [ ] **BP-T144** Write `docs/guard/provider-integrations.md` and
  `docs/guard/extensions/provider-integration-contributing.md`. Add a provider integration
  pull-request template section and a "Provider integration contributions" section to `AGENTS.md`.
  Leave `publisher.verified` as `false` in every contribution.

### Phase 3 qualification

- [ ] **BP-T150** Acceptance suite against the testkit provider: connect, verify, each capability,
  each verdict, each failure state, disconnect.
- [ ] **BP-T151** Privacy suite: for every capability the serialized request equals the declared
  share set exactly; excluded origins produce no request.
- [ ] **BP-T152** Outage suite: with the provider unreachable every decision equals the no-provider
  decision plus a `provider_unavailable` finding; with "Require a fresh check" on, the first action on
  a subject is a review.
- [ ] **BP-T153** Gauntlet phase 3 cases in `ci/gauntlet/browser.json`, against the fixture provider
  (BP-T179): `browser-quiet-provider-ok`, `browser-quiet-provider-unknown`,
  `browser-quiet-provider-down`, `browser-quiet-unverified-caution`, `browser-task-verified-caution`
  (budget 2), `browser-task-caution-storm` (budget 3), `browser-task-two-providers` (budget 2),
  `browser-blocked-provider-danger`, `browser-blocked-provider-danger-enforced`. The judge also
  checks the stub's request journal against the declared share set. Evidence: provider-added prompts
  0 against each no-provider twin; caps hold in the storm case.
- [ ] **BP-T155** No-added-prompt differential in CI (BP-T180 check 4) for every shipped manifest and
  for the fixture manifest: the browser gate corpus decided with no provider, then with the provider
  answering `ok`, `unknown` and failing, gives identical decisions. Evidence: the test fails when
  `provider_integration_decide` is changed to review on `unknown`.
- [ ] **BP-T154** First real provider onboarding dry run: with a provider's confirmed API contract,
  author its manifest, run BP-T150 to BP-T152 against a recorded-response fixture, and list every
  place the declarative contract was not enough. Each gap becomes either a contract change or an
  adapter proposal.

## Phase 4: protocol layer

- [ ] **BP-T080** Generate `contracts/browser-drivers/cdp-methods.v1.json` from pinned upstream
  protocol files with a script under `scripts/` that records the upstream revision and digests. Add
  `rust/crates/guard-command/src/browser_cdp_methods.rs` with the verb table from PRD 5.6. A test
  enumerates every method in the pinned files and fails on an unmapped one. Unknown methods are
  `Other` and privileged.
- [ ] **BP-T081** Resolve `cdpPassthrough` tools through the table (BP-T012). Vectors: a forwarded
  screenshot is routine inspection; a forwarded cookie read is privileged with the `cookies` surface.
- [ ] **BP-T082** After ADR 0017 is accepted: create `rust/crates/guard-browser-relay` (framing,
  target tracking, discovery endpoint rewrite) with decisions delegated to `guard-runtime`.
- [ ] **BP-T083** `hol-guard browser relay --upstream <endpoint> [--listen-port <n>]` behind a flag,
  off by default. Hold, forward, or answer with the protocol error from PRD 5.6. Relay failure closes
  the connection and never falls through. Per-listener client capability, one client at a time, and
  peer-user check from ADR 0017. Tests: a client without the capability, a second concurrent client,
  and a different-user peer are all refused before a frame is read; destination-origin decisions for
  `Page.navigate` and `Target.createTarget`; per-frame origin tracking.
- [ ] **BP-T084** Bounds and budget: frame cap, memory cap, queue cap, no stored payloads, p95 under
  1 ms per forwarded frame under a live grant. Soak test and latency evidence.
- [ ] **BP-T085** Managed mode: rewrite a recognized driver's endpoint flag at MCP admission to the
  relay. Opt-in setting.
- [ ] **BP-T086** Script inventory facts from the relay (`page.script_hashes`) feeding
  `browser.script-integrity`. Bounded at 256 hashes.
- [ ] **BP-T087** Gauntlet phase 4 cases: a script-driven browser through the relay has a cookie read
  held and denied (`browser-blocked`); routine navigation flows under a site grant with zero
  interruptions (`browser-quiet`); a forwarded screenshot is quiet under a grant. The relay cases use
  a scripted protocol peer in `ci/gauntlet/browser_fixtures.py`, not a real browser. Gate rows for
  each `cdpPassthrough` shape. Evidence: budgets `within` with the relay flag on, and unchanged with
  it off.

## Phase 5: page layer (planning only)

- [ ] **BP-T090** Write an ADR for the companion browser extension: Manifest V3, native messaging
  host, closed fact list, the in-page banner that never renders approval buttons, store distribution,
  and update policy. No code in this work.

## Close-out

- [ ] **BP-T200** Re-measure BP-T008. Evidence: approvals per scripted task at most 1 with a site
  grant; hook latency p95 within 5 ms of baseline.
- [ ] **BP-T201** Confirm every row in PRD section 9 is written, and that each new document is linked
  from `README.md` or from the existing guide that covers the same area.
- [ ] **BP-T202** Confirm both rollback switches restore prior behavior on a released build.
- [ ] **BP-T203** Run the installed-Guard check on a released alpha for one driver profile and the
  testkit provider flow, and record the Guard version and `browser explain` results.
- [ ] **BP-T204** Release-gate evidence (PRD 8.5, 8.7): core qualification `qualified: true` and
  `independent_verifier: true`; the full-task discover run on three harnesses with no new browser
  class in any `false-positives.json`; the `browser` and `approval-retry` profiles on Claude Code,
  Codex and Cursor with every browser budget `within` and none `unmeasured`.
- [ ] **BP-T205** Fatigue evidence: approvals per completed task and quiet-case rate per driver id
  from the browser lane, next to the BP-T008 baseline. Target: single-site task 1, two-site task 2,
  granted-site and local-page tasks 0.
- [ ] **BP-T206** Ledger closed (BP-T188): every browser false-positive class found during this work
  has a fix pull request, a gate row id and a live case id. `ci/gauntlet/known_gaps.json` has no
  browser entry, or each one names its tracking issue.
- [ ] **BP-T207** Conformance evidence: `hol-guard integrations conformance` passes for every shipped
  manifest from the released CLI, and the calibration report is attached for every provider marked
  `verified`.
