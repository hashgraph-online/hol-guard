# Swarm: local agent workspace

## Product architecture

Swarm is the place to see and direct AI agents working on this computer. A
person can follow one agent, coordinate several agents in one project, or move
between projects without losing track of work, approvals, and context access.

Base: `main` at `274261c0ef28b3d33c36e06a77599c4d02e68685`.
Branch: `feat/swarm-agent-workspace`.

Rebased on 2026-11-10. This main includes the newest alpha,
`alpha/v3.60.0a66` (`274261c0ef28b3d33c36e06a77599c4d02e68685`).
The Swarm feature and CIGAR handoff are retained; generated dashboard assets were
rebuilt to resolve bundle conflicts. Navigation identifies Swarm as Alpha.
Validation uses upstream's pinned Rust 1.89.0 toolchain and locked dependencies.

### Experience

Add **Swarm** to primary navigation at `/swarm`. The desktop layout has a
project rail, an agent map, and an inspector. Project lanes group agents by
workspace; connectors indicate membership in a project, not an inferred
agent hierarchy. A list view provides the same actions and facts. The selected
agent remains selected across refreshes. Mobile stacks the cards and detail
panel; map and list controls remain available.

The header shows running agents, agents needing attention, and active projects.
Each agent shows its harness, task, workspace, last observed activity, and
whether Guard can control it. Text accompanies status colors. Recent activity
and approvals take precedence over decorative metrics. Unknown progress,
unreported token usage, and unavailable CIGAR usage stay unknown.

**New agent** opens a task composer: installed harness, project directory,
task, optional model, and a clear preview of how it will run. Launches use the
harness's normal protection and credential setup. The composer explains missing
setup and concurrent work in the same directory. It never adds permission
bypass flags or silently creates shared worktrees. The user can launch agents
in separate existing worktrees to isolate simultaneous edits.

The inspector shows a bounded activity stream, pending approvals, lifecycle,
and context access. A message composer directs a managed agent through its
documented transport. Busy steering, next-turn instructions, interruption, and
stopping are distinct capabilities with accurate delivery states. Unsupported
external sessions have an explicit handoff to their harness rather than a
button that pretends to control them. Approval links open Guard's existing
review UI, which retains Allow once and Always allow.

### Native service and ownership

Use a small Rust Swarm service integrated into the existing resident, plus thin
Python HTTP framing and a lazy React workspace. Process discovery, identity,
launch validation, lifecycle, cancellation, and persistence belong in Rust.
Reuse the existing contained-process and secure-filesystem primitives where
their contracts fit. Keep Swarm off the synchronous hook decision path.

The service combines three separate kinds of evidence:

1. Managed runs: a child and transport Swarm owns, with a generated run ID,
   process identity, workspace, adapter, task, timestamps, and lifecycle.
2. Observed processes: recognized harness processes visible to the current OS
   account. Process identity includes start time, not PID alone. A matching
   name is discovery evidence, never authorization to send input or a signal.
3. Guard reviews: existing pending actions for the same workspace and harness,
   with links into Inbox. These are explicitly project reviews, since they
   cannot be attributed to a particular process without a session binding.

Deduplicate managed processes against discovery and avoid counting helper
processes as separate agents. Preserve uncertainty when a session cannot be
correlated. Report coverage and freshness so “all agents” means all recognized
agents visible to this account, with transparent limits for inaccessible or
unsupported applications. Do not scrape private transcripts or credentials.

Initial managed adapters target Codex and Claude Code. Verify their installed
CLI/help and official protocol contracts before enabling controls. Use typed
arguments and structured stdin/stdout, never a shell command assembled from
task text. The adapter contract declares launch, follow-up, busy steering,
interrupt, output events, and usage support independently. Other known
harnesses can be observed and directed back to their native surface; add
managed adapters only with a verified protocol and tests.

Managed lifecycle: starting → running → awaiting input/completed/failed/stopped.
An in-flight action has an ID and an acknowledgement; reconnecting does not
replay a launch or an instruction. Bound live runs, pending messages, output
bytes, event retention, and request duration. Stop affects only a service-owned
process tree. On service shutdown, close transports and reap owned children;
on recovery, report interrupted runs instead of relaunching tasks. Keep private
summary metadata under Guard's home; keep transcript content bounded and
session-local unless a separate explicit retention setting is introduced.

### HTTP and UI contracts

Use versioned `/v1/swarm` endpoints for snapshot, launch, run activity,
instructions, interruption, and stop. Dashboard authentication and native
route authorization apply to every request. Swarm requires the local dashboard;
hosted origins, approval-link sessions, and scoped repair sessions cannot
enumerate or control agents. Browser-supplied run IDs
never become executable paths or process IDs. Mutations are idempotent by
request ID and carry revision checks where stale state changes semantics.

The React client validates payloads and polls bounded snapshots while visible;
an aborted, delayed, or out-of-order request must not overwrite newer state.
Disconnects preserve the last snapshot with a visible stale marker and disable
controls until the service is confirmed. Launch and steering drafts stay in
memory, not localStorage or URLs. Output is rendered as text, never HTML.

### CIGAR

Use the merged context-assistance service and existing workspace/agent scope
contracts. Show runtime availability, per-project and per-harness grants, and
observed context events as different facts. Shared-note permissions remain in
the existing Context access screen. A grant
means access is available; it does not prove a particular agent used CIGAR.
Do not label generic provider token counts as CIGAR savings or attribute
project-level evidence to one process without a session binding.

Swarm links to existing Context setup and permission flows. It does not enable
CIGAR, grant sources, authorize other agents, or share notes implicitly when a
run starts. Multiple projects keep separate scope identities.

An inspector's **Add to CIGAR** action carries its project, app, and return
selection into CIGAR's Projects screen in tab memory. The folder is preselected;
the user chooses files and confirms the existing approval gate. An existing
every-app pick is reused and shown first. Unknown project paths still require
a folder choice. The context preview and return action complete the workflow.
Prompt-hook apps receive context on subsequent prompts when Guard is connected;
other apps still require their own MCP connection and explicit pairing. Process
discovery does not establish either connection. Swarm recognizes every-app picks
and matching app scopes without treating either as proof of that agent's use.

### Visual system and accessibility

Use Guard's existing typography, surfaces, blue accent, focus treatment, and
calm product voice. Give the map a clear visual hierarchy with project anchors,
agent nodes, restrained activity indicators, and a readable inspector. Avoid
filler charts, invented success metrics, and continuously moving layouts.
Respect reduced motion. Every graph action has a keyboard-accessible control
and list equivalent. Dialogs trap and restore focus; updates do not steal
focus. Verify narrow screens, zoom, long names, large swarms, and empty/error
states in a browser. No extra visualization framework is needed initially.

## Implementation plan

1. **Contracts and discovery.** Define typed snapshots, adapter capabilities,
   stable identities, and limits. Implement and test current-user process
   discovery, helper deduplication, stale records, and project grouping. Trace
   existing session and CIGAR interfaces before adding new ones.
2. **Managed execution.** Implement tested Codex and Claude adapters, safe
   launch validation, bounded output, instruction acknowledgements,
   cancellation, private metadata, and recovery. Test with disposable harness
   doubles, then use a real installed CLI only for a bounded, explicitly
   authorized smoke task; do not incur provider usage during ordinary tests.
3. **Resident and HTTP integration.** Add native service ownership and thin
   authenticated routes. Test dashboard authorization, denied scoped sessions,
   duplicate actions, unknown IDs, teardown, and unavailable native runtime.
4. **Swarm workspace.** Add navigation, live map/list, project filters, search,
   inspector, task composer, steer/stop controls, stale/error/empty states,
   approval links, and precise CIGAR access/usage presentation.
5. **Validation and refinement.** Run native contract/lifecycle tests, HTTP
   integration tests, TypeScript checks, targeted dashboard tests, browser
   flows and screenshots at desktop/mobile sizes, and the production build.
   Exercise disconnected, unsupported, and concurrent-project cases. Rebuild
   shipped assets, review the diff, and keep raw logs/screenshots outside Git.

## Acceptance criteria

- `/swarm` is a polished, navigable, accessible workspace using live local data.
- Multiple recognized agents are visible with honest liveness, project,
  ownership, and capability states; one agent is equally usable.
- Supported installed harnesses launch real managed work, report activity,
  accept supported follow-up/steering, and stop their owned processes safely.
- Unsupported controls explain the limit and offer an appropriate handoff.
- CIGAR availability, access, and observed use are distinguished and scoped.
- Existing approval semantics, dashboard authorization, and project boundaries
  are preserved. No shell injection, raw-PID control, or permission bypass.
- Tests cover consequential lifecycle and authorization risks; browser checks
  cover actual interaction and responsiveness. Report remaining platform or
  harness qualification limits explicitly.
- Keep the patch focused: one architecture/implementation document, compact
  fixtures, modular source files normally below 500 lines, and no raw evidence
  archive. Do not merge, publish a release, or alter live agent settings as part
  of development.

## Implementation status

Architecture, implementation, and browser refinement are complete on the branch
above.

### Delivered behavior

- Lazy `/swarm` workspace with project map/list, search and attention filters,
  recent activity on cards, activity/context/details inspector, project reviews,
  task composer, instruction queue, interruption, and confirmed stop.
- `guard-swarm` owns discovery and managed execution. Python only frames native
  requests and HTTP responses. Discovery recognizes nine CLI families and
  collapses known JavaScript launcher/native-child pairs. Observed processes
  expose no task text or controls; they may be idle or serve multiple sessions.
- Managed Codex uses `exec --json` and exact-session `exec resume`; Claude Code
  uses `-p --output-format stream-json --verbose` and exact-session `--resume`.
  Tasks travel over stdin. Neither adapter changes CLI settings, permissions,
  sandbox policy, hooks, credentials, or context grants. Noninteractive CLI
  permission limits still apply; inspect activity and continue in the native
  harness when a tool needs permissions the CLI cannot request in this mode.
  The daemon supplies its own PATH through the bound native request; browser
  input cannot override it. Rust uses only absolute entries for installed-CLI
  discovery and owned child execution, without relaxing the resident's isolated
  environment. Provider credentials that exist only in shell environment
  variables are not forwarded; use the CLI's persisted sign-in/configuration.
- Busy instructions queue for the next successful turn. In-turn steering is
  unavailable; interrupt and then send a follow-up to change direction.
  Failed, interrupted, denied, or stopped turns discard unsent instructions.
- A service epoch, request receipts, and run revisions prevent duplicate or
  stale actions. Unconfirmed browser actions retry the identical request.
  Observed PIDs can never become signal targets. Unix children use an owned
  process group; Windows uses the existing suspended-child job primitive.
  Active runs prevent idle resident retirement. Explicit shutdown terminates
  owned work and joins its workers before draining resident requests, even if
  another request retains the policy store. New workers cannot start afterward.
- CIGAR counts successful, correlated responses from known Guard context MCP
  tools (`get_guard_context`, `explain_guard_context`, `explain_guard_action`).
  Grants, connection pairing, and actual reported use remain separate. Hook
  injection and custom server aliases are not counted; model tokens are not
  presented as context savings.
- Private `swarm-history.v1.json` checkpoints contain bounded summaries, not
  prompts, output, model/token data, resumable session IDs, or PID authority.
  Restart restores inert summaries and rejects requests from the previous
  epoch. It never relaunches work. A forcibly killed resident can leave orphan
  processes, which are discoverable but cannot be reattached for control.

Limits: 256 observed processes, 16 concurrent managed runs, 64 retained managed
summaries, four pending instructions per run, 200 retained events per run,
16 KiB tasks (2 KiB display previews), 4 KiB event text, 256 KiB output lines,
16 MiB per output stream per turn, and
24 hours per turn. An epoch accepts at most 2,048 distinct mutations; receipts
are never evicted within that epoch. Project directories must already exist.
Swarm does not automatically create worktrees or coordinate conflicting edits.

### Verification

- Rust Swarm: 17 tests cover process discovery, daemon PATH transport, literal stdin, exact resume,
  duplicate/stale/foreign actions, output limits, owned descendant shutdown,
  inert recovery, CLI permissions, and truthful context counts.
- Native resident: three tests cover scoped home binding, reply identity, schema
  validation, local-dashboard authorization, and owned-tree cleanup while another
  request retains the policy store. Approval and repair sessions are denied.
- Rust 1.89.0 workspace formatting and Clippy for `guard-swarm` and
  `hol-guard-runtime` pass, including all targets with warnings denied.
- Python: 12 native reply binding, error handling, and HTTP framing tests pass,
  along with 128 existing native transport and review-boundary tests. All 85
  ownership-gate tests and the full native ownership gate pass with Swarm's
  Rust service and Python transport registered in the ownership contract.
- Dashboard: model/parser, existing routing and navigation checks; five browser
  journeys exercise desktop, 390px/320px layouts, launch, instruction queue,
  stop confirmation, uncertain retries, stale state, filters, CIGAR, and dialog
  keyboard behavior. Screenshots remain outside Git.
- Five additional browser journeys cover observed-agent context handoff, file
  selection and approval, preview citations, return-to-agent status, reuse of
  existing grants, refused grants and failed previews, unknown folders, MCP
  pairing guidance, keeping the handoff while CIGAR is off, and recovery from
  temporary native startup contention without replaying controls or grants.
- The full dashboard test command (`bun run test`) passes. Swarm model tests
  now run as part of that command in CI. The rebase also passes the 20 existing
  CIGAR workspace browser journeys, for 30 browser checks in total.
- Production Vite build passes and shipped assets are rebuilt. Existing shared
  chunk hashes change with the dashboard entry point; no generated evidence,
  vendored dependencies, or old CIGAR branch content is included.
- TypeScript with Node types reports the same 60 diagnostics as clean main,
  with no new diagnostics. The default TypeScript invocation also inherits
  main's missing Node-type configuration.

After rebasing onto main at `alpha/v3.60.0a66`, an isolated live macOS dashboard verified authenticated Swarm
reads, real process inventory, and installed Codex detection through the resident/HTTP path.
The context regression then exercised an observed agent's handoff, both saved
projects (eight selected files each), successful cited previews, and return to
the same inspector. A cold-start check recovered automatically from five
temporary busy responses and completed both previews. Status reads retry within
their original ten-second deadline; navigation cancels pending retries, and
controls and grants are never replayed by this recovery.

Use an optimized native runtime for source-checkout UI previews:

```sh
cargo build -p hol-guard-runtime --bin hol-guard-runtime --release --offline --config profile.release.lto=false --config profile.release.codegen-units=16
```

Run that command from `rust/` after installing the locked dependencies and point
the preview's `HOL_GUARD_NATIVE_BINARY` at `rust/target/release/hol-guard-runtime`.
The initial debug preview exceeded the six-second actor deadline while scanning
saved project files, which closed the optional CIGAR worker. A runtime sample
located the delay in source scanning; the optimized build restored both projects
and compiled each preview in under a second with the same checks and deadlines.
Keep the preview's Guard home bound for ambient native calls too, using
`bind_context_digest_home(guard_home)` before constructing its store and daemon.

Qualification limits: execution tests use disposable CLI doubles on macOS;
browser tests use API fixtures. Real provider-backed sessions and Linux/Windows
execution have not been qualified here. No live harness settings were changed
and no billable tasks were launched. The Unix process-group guarantee does not
extend to a child that deliberately detaches into a separate session.

Adapter contracts were checked against the official
[Codex noninteractive documentation](https://developers.openai.com/codex/noninteractive/)
and [Claude Code programmatic usage documentation](https://code.claude.com/docs/en/headless).
