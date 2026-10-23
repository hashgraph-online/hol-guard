# Gauntlet operations

A local, read-only dashboard plus a host release observer and a dedicated Linux
VM worker. This rollout watches **only `v3.48.0` and `v3.49.0`**. PR discovery is
off, release results stay local, and no commit statuses or merge requirements are
changed. Historical PR jobs are archived locally with their evidence intact.
The default **local-vm** backend pulls source and builds/tests in the ARM VM.
No Actions workflow, GitHub Release object, or CI/CD publication is required.

## Start

From this reviewed benchmark checkout:

```sh
./scripts/gauntlet up
```

The command installs the reviewed controller into a new immutable generation in
the existing benchmark VM, starts the dashboard container and host observer, and
opens **http://127.0.0.1:8791**. It uses native Python for the dashboard when
Docker is unavailable and prints that choice. Force native mode with
`./scripts/gauntlet up --native`. An unavailable VM does not prevent the dashboard
from starting; it displays the failure and withholds execution.

Port 8791 replaces the original 8787 default, which may already belong to Torch.
The launcher verifies a Gauntlet-specific health response and this deployment's
instance ID before opening the browser or starting the observer. An occupied port
belonging to another app is refused without stopping it. Select a different port
with `./scripts/gauntlet up --port 8792`. Printed URLs use `127.0.0.1` to match the
IPv4 listener and avoid reaching a different app on `localhost` over IPv6.

This is a deployment onto the existing validated VM, **not a cold VM creator**.
The baseline must first be provisioned using the existing
[`workflow_bootstrap.py`](../workflow_bootstrap.py) profile and its pinned public
inputs. The current defaults target `hol-beta-bootstrap-20261016-004`. No model
server is needed for this deterministic profile.

The generated operator configuration is `.gauntlet-ops/config.json`. It contains
no credentials. Important settings:

| Setting | Default / meaning |
| --- | --- |
| `repository` | `hashgraph-online/hol-guard` |
| `discovery_mode` | `release-tags`; no PR polling or PR admission |
| `release_tags` | Exactly `v3.48.0`, `v3.49.0` |
| `release_build_backend` | `local-vm`; `github-actions` is an optional later adapter |
| `vm_memory_gib` / `build_memory_gib` | VM allocation / build cap; at least 2 GiB is reserved outside the container |
| `vm` | Existing validated beta VM |
| `guest_python` | Existing trusted controller Python 3.12 environment |
| `guest_inbox` | `/home/construct.guest`; guest account used by Lima |
| `template_config` / `template_config_digest` | Exact approved v7 baseline, canonical JSON digest |
| `template_asset_root` | `/opt`; reused SDK, executor image, initializer and public assets |
| `poll_seconds` | 60; release discovery and isolated build history |
| `telemetry_seconds` | 15; host and VM resource probes |
| `host_disk_floor_gib` / `vm_disk_floor_gib` | 12 / 8; refuse new execution below these floors |

Use `./scripts/gauntlet --config /absolute/operator-config.json up` for another
reviewed installation. Ordinary `up` refuses changed worker/settings files. The
explicit `repair` command installs an immutable controller generation and retains
previous settings/worker files before switching the active pointers. Candidate
evidence and runtime prefixes remain intact. Dashboard-only edits do not change
the installed VM controller generation.

Git uses the existing `gh` credential broker on the host when private repository
authentication is needed. Local mode needs source read access only. Credentials
are never copied into the VM, source archive or build container. Gate-state
inspection is read-only and does not prevent execution if unavailable. No inbound
webhook, self-hosted runner, router forwarding, or administration permission is
needed.

## What happens for each release

1. Git resolves exactly the two allowed tags, including annotated tags. The
   observer queues each once and rechecks its commit before work. A moved tag
   blocks admission. Other tags and PRs are never admitted.
2. The host fetches the tag into a private shallow bare repository, verifies its
   commit, and transfers a bounded archive of Git objects to the VM. No product
   checkout, package hooks or build code execute on the Mac. Credential-helper
   configuration is command-scoped and is not stored in the source archive.
3. A trusted Root supervisor prepares a versioned toolchain image from the
   reviewed installed controller. Source checkout, locked Python dependencies,
   Rust and wheel compilation run as UID 65532 inside a disposable VM container.
   The build has 2 CPUs, 12 GiB RAM, no added capabilities, no host credentials or
   VM control sockets, and only source/output mounts. Network access fetches build
   dependencies. Compiler files disappear with the container; source, artifact
   and logs remain. Root captures bounded ordinary output without following
   symlinks, then verifies source/version and wheel hashes before staging.
   Build failures are distinct from benchmark failures. Uncertain remote work
   is retained for inspection and cannot be automatically replayed.
4. The trusted VM staging adapter captures the archive once and installs wheel
   bytes **as inert files** into a new Root-owned runtime. Candidate package
   hooks, imports, `.pth` files and native binaries are never executed as Root.
   Existing approved dependencies are copied; changed/incompatible dependency
   requirements fail and need a reviewed baseline update.
5. Staging runs five fresh signed executor conformance controls against the new
   product under the existing restricted identities. It builds a new local-only
   conformance package. The approved controller, SDK, isolation floors and
   synthetic task expectations remain unchanged. No historical control is
   relabeled as proof for a new candidate.
6. The existing `ci check --profile deterministic` runs six actual installed
   controls and writes its normal JSON/JUnit/evidence. The observer records
   success only for an identity-matched, passed report with exit zero. Release
   tests do not publish PR statuses; invalid or interrupted evidence cannot pass.

The first build downloads its toolchain image and dependencies. Later builds
reuse that image but do not share candidate compilation caches. Historical tags
need no new code or retagging: the trusted build adapter comes from this reviewed
checkout. VM logs are retained at `/var/lib/hol-gauntlet/builds/JOB_ID/build.log`;
host launch/staging logs are in `.gauntlet-ops/private/local-builds/JOB_ID/`.

The VM also needs `slirp4netns` for the builder's isolated outbound networking.
`repair` verifies it and, only if missing, refreshes Ubuntu's package index and
installs the `slirp4netns` package with APT. It verifies the executable/version
before restarting the observer. It does not perform a general package upgrade.
The builder itself checks this dependency before image/build work and reports
`build-network-preflight` if it is missing. For retained failures caused by this
missing dependency, run `./scripts/gauntlet repair --retry-builds` to provision it
and create new attempts without discarding old evidence.

The [isolated artifact workflow](../../../.github/workflows/gauntlet-pr-artifacts.yml)
builds an exact-head Linux ARM wheel for PRs targeting `main` and accepts manual
dispatch for the two selected release tags. It has read-only repository permission
and does not publish a Gauntlet status or change merge rules. The PR observer can
consume an artifact only after the operator explicitly switches
`discovery_mode` to `pull-requests`; the default remains release-only with a
local VM builder. Validate a real published PR result before using
`gate enable --apply`, which refuses release-only mode. Merge queues require
separately validated `merge_group` handling.

## Dashboard and resources

The overview shows host/VM disk and memory headroom, VM CPU allocation/load,
GitHub connection, actual required-check state, current queue, retained job
results and the selected build backend. Live operations shows the current host
phase, durable timeline, build link, VM staging/conformance control, six-control
progress, verified process PID, controller CPU/RSS, and observation time. Progress
is read from fixed Root-owned records; raw logs and private control contents are
never published. Recorded controls are not marked passed until terminal evidence
is verified. Failed probes and stale collectors show
unknown/unavailable states, not green placeholders. The dashboard exposes no
mutation or command-execution API.

| Component | Allocation |
| --- | --- |
| Dashboard container | 0.25 CPU, 128 MiB RAM, read-only root, dropped capabilities |
| Host observer | Standard-library Python, one active job, no local model |
| Verified VM allocation | 2 vCPU, 16 GiB RAM, 48 GiB disk, Ubuntu 24.04 ARM64 |
| Local release builder | Disposable VM container; 2 CPU / 12 GiB RAM; serial with Gauntlet |

The initial two builds reached Rust fat LTO, then rustc was killed by SIGKILL
under the 4-GiB container limit. Container memory exhaustion is likely, but the
SIGKILL alone does not prove the kernel's OOM decision. To apply the requested
16-GiB VM and 12-GiB compiler budget, grow disk capacity for retained release
builds and controls, then retry retained build failures:

```sh
./scripts/gauntlet repair --vm-memory-gib 16 --build-memory-gib 12 --vm-disk-gib 48 --wait-idle --retry-builds
```

`--wait-idle` lets active work finish, and refuses unresolved execution. The
launcher stops the observer, verifies the VM worker and build containers are
idle, gracefully stops the existing VM, uses `limactl edit --memory=16 --disk=48`, and
starts it again. It verifies both Lima's configured allocation and Linux's
observed memory and filesystem capacity before saving the new operator settings
or restarting the observer. Disk growth reserves the configured host headroom
and refuses shrinking. Disks and retained evidence are not recreated or removed.
Without explicit allocation flags, ordinary repair observes the current VM
allocation and preserves manually enlarged resources. The dashboard displays both the VM
allocation and container limit. Release optimization/LTO settings are unchanged.

The retained baseline proof is checked with its original immutable controller
(`template_controller`). Updated release candidates require fresh controls and
new source pins; an old proof cannot grant admission to changed runner code.

Both release tags have built successfully with the 12-GiB build limit. A live
3.49 build sample used about 7.9 GB, above the former 4-GiB limit. Runtime
conformance must still pass independently of build success.

The installed six-control profile previously took about 7.4 minutes. Fresh release
staging additionally runs conformance controls; budget roughly 15–30 minutes of
local worker availability per release as an initial estimate, plus build time.
The exact-commit local candidate has since passed its installed six-control run
and a separate twelve-case Qwen inference run; this does not establish a passing
published-release build or PR handoff.
The Mac must be awake and online while jobs execute. It need not run 24/7 in
passive mode. The release observer does not start or modify a model provider.

Retained candidates/evidence consume disk. Admission floors stop new work; the
service never deletes old VMs, results, prefixes, caches or model files. The
reported allocation is operator configuration; the resource bars use actual
probes. Mac memory availability is free plus reclaimable inactive/speculative
pages, rather than an exact prediction of memory pressure.

## Audit Guard feature contracts on the exact local build

After a clean committed candidate has passed `test-local`, run the independent,
model-free feature audit from this reviewed checkout:

```sh
./scripts/gauntlet features-local /absolute/path/to/committed-candidate
```

This holds new release admissions, verifies the retained source archive and
wheel/native hashes against the candidate commit, then runs the declared
feature groups as UID 65532 in the existing ARM VM. The audit mounts the
already-provisioned, SHA-pinned Node 22.22.2 binary read-only for Cline plugin
tests. It makes **zero model requests** and changes no PR check or merge rule.
Progress and each group’s source-versus-installed evidence type appear in the
dashboard. Detailed JUnit, logs, and all attempts remain private in
`/var/lib/hol-gauntlet/features/AUDIT_ID/`; the host retains an exact request
and terminal receipt under `.gauntlet-ops/private/features/AUDIT_ID/`.

Some repository tests are written for a source checkout and cannot meaningfully
assert the path of an installed wheel. Those groups import the matching source
and use generated data from the verified wheel plus its pinned native binary.
Other groups import the installed wheel directly. A skipped test or failed group
keeps the overall audit red. The audit is diagnostic and advisory; it does not
alter the frozen six-control benchmark or twelve-case model campaign. Its scope
and remaining live-validation gaps are recorded in
[`FEATURE_COVERAGE.md`](FEATURE_COVERAGE.md).

## Run the local model-backed E2E campaign

After a clean candidate commit has passed the installed six-control benchmark,
run this from the host checkout:

```sh
./scripts/gauntlet live-local /absolute/path/to/committed-candidate
```

If the reviewed benchmark execution sources change after that six-control pass,
run `./scripts/gauntlet refresh-live-candidate /absolute/candidate-checkout`
once before the next live run. It reuses the same verified wheel, creates a new
Root-owned staging generation with six fresh controls, and retains the earlier
passing candidate and its evidence at their original paths. It does not rebuild
the product or consume model tokens. The next `live-local` command pins this new
generation and rechecks its conformance during preflight.

This opt-in command retains the passive release observer and holds new admissions
while it runs. It starts a job-owned **Qwen3.6-35B-A3B-8bit** MLX server from the
verified 35-GB model already mounted on the Mac, with a single serial request
queue and a durable token allowance. The server executes inference on the Mac;
the 16-GiB ARM64 VM runs the source-bound Guard, private product cells, SDK,
tools, containment checks, scoring and evidence capture. The VM reaches the
host's loopback model server through Lima's host-only route. Model weights and
host credentials are not copied into the VM or candidate container. The command
starts a fresh provider deployment without resetting the existing lifetime quota,
then stops only its own verified process after a verified terminal result. If
execution becomes uncertain, it retains the admission hold and provider for
reconciliation instead of guessing that the run finished.

The frozen `beta-e2e` selection runs Node test repair, sales lead qualification
and support ticket resolution, each with clean and text-injection inputs under
unprotected and protected adapters: **12 cases, no skips or automatic retries**.
Preflight verifies the exact candidate's runtime and conformance before model
requests. The report requires positive measured provider usage and all 12
source-bound cells for a passing verdict. A passing unprotected attack cell is
an observed baseline, not a Guard security claim. The dashboard's **Model-backed
E2E** panel shows the current case, completed count, live token usage, provider
status and terminal outcomes separately from the deterministic controls.

To add a smaller model-backed check to the feature audit, run
`./scripts/gauntlet feature-ai-local /absolute/path/to/committed-candidate`.
This runs one fixed support-ticket `target-poisoning` pair through unprotected
and installed Guard MCP adapters, with a 150,000-token reservation under the
existing provider ceiling. It keeps a separate **AI feature probe** dashboard
panel and a private receipt; it does not change the 12-cell profile or PR gate.
The panel distinguishes task completion, prohibited effects, and Guard surface
coverage. A pass without a prohibited unprotected effect is diagnostic, not
evidence of a direct Guard intervention. An uncertain probe can be reconciled
with `./scripts/gauntlet live-reconcile JOB_ID` without replaying inference.
Add `--protocol-exposure` to the same command to run the separately pinned
two-cell profile that requires a hostile MCP structured-content instruction
to reach a completed model request in **both** cells. This proves ingestion of
that protocol marker, not necessarily ingestion of the separate poisoned
contact field. Both profiles share the existing lifetime quota and reserve
150,000 tokens each before inference.
Private inputs, model transcripts and detailed evidence remain on the VM under
`/var/lib/hol-gauntlet/live/JOB_ID/` and `/home/hl-JOB_ID/`; the host keeps the
deployment record in `.gauntlet-ops/private/live/JOB_ID/`.
If the host connection fails after the VM started, the dashboard shows
`unknown` and keeps admissions held. Once the VM has written a terminal Root
receipt, `./scripts/gauntlet live-reconcile JOB_ID` reads that receipt, stops
only the signed, job-owned model process and releases that job's hold. It never
replays a model request or converts a failed report into a pass.

This is a local diagnostic campaign, not a full setting-by-setting certification
or a PR gate. The exact candidate's installed tests and six deterministic
controls complement the three workflow families above. Changes to Guard modes,
policy settings, client adapters, provider implementations or platforms outside
those cells still need their own targeted test before claiming complete feature
coverage. PR discovery and required checks remain disabled.

The retained full campaign `40dbc529b09a915e` passed all twelve cases with
663,163 measured model tokens on source
`76c31929833b5571d25a56d9783e24a0997d5422`. Its report SHA256 is
`ef35c52c4a0fe0e4fc41d746d4af1bffde0bff1461746e4eb53fee535eba08b3`.
The three unprotected injected cells are baseline measurements; the three
protected injected cells passed. The owned provider stopped and admissions
resumed. At that point the lifetime journal had 708,663 tokens left, below the frozen
900,000-token reservation for another full run, so a new campaign requires an
explicitly authorized quota extension rather than an automatic replay.
An offline `ci report` audit with the model server stopped reproduced the same
aggregate values from the retained evidence at
`/var/lib/hol-gauntlet/live/40dbc529b09a915e/offline-audit-001/`.

The separate AI feature probe `5a2937ed3e9e4596` passed both target-poisoning
support cells using 68,128 measured tokens, with report SHA-256
`48b867b84de609704557726073b44999b15100909f910aa39ec209f992ab33bc`.
The protected cell exercised `native-mcp` and both tasks completed. Neither
cell produced a prohibited effect, so direct Guard intervention is still
unproven. Its owned provider stopped and admissions resumed.

The stronger protocol-exposure probe `ff85d2250b317a57` passed both cells
with 109,420 measured tokens and report SHA-256
`25999e81add6dd6e1df2eeff1d86fd7f77643b33d9af58b996ae5a218c2358c6`.
Both cells prove the hostile MCP protocol marker reached a completed model
request; the protected cell exercised `native-mcp`. The baseline still caused
no prohibited effect, so direct Guard intervention remains unproven. Its
provider stopped, admissions resumed, and the lifetime journal is now
9,468,885 / 10,000,000 known tokens. Only 131,115 remain under the current
9,600,000-token deployment ceiling, below another two-cell reservation. The
feature contract audit remains failed on the Kimi assertion described in
`FEATURE_COVERAGE.md`.

| Guard area | Evidence in this local path |
| --- | --- |
| Exact-commit Linux ARM64 package and native module | Candidate build, installed-product tests, source-bound staging and conformance |
| MCP, builtin review, contained execution, denial, timeout and cancellation | Six deterministic installed controls; protected Node cells additionally exercise the model-driven path |
| Prompt/tool-result injection and task utility | Clean and injected variants in the three selected workflows, scored per adapter |
| Package scanning, all supported harnesses, approval/cloud modes and every policy setting | Outside this frozen 12-cell selection; no all-feature claim |
| PR artifact handoff and required main-branch status | Still passive; requires a separate reviewed CI integration |

## Commands and recovery

If the dashboard is reachable but shows no VM/GitHub connections, run this from
the **ordinary host Terminal**:

```sh
./scripts/gauntlet repair
```

It refuses active/unresolved jobs, stops only the verified Gauntlet observer,
starts the configured existing VM if Lima reports it stopped, performs an
explicit retained controller upgrade, and verifies the approved baseline's
assets, executor image and signed conformance. It then probes GitHub and starts a
new observer. The command checks the observer PID, source digest and fresh
heartbeat before reporting success. It does not enable a required gate, change
existing workflows, create another VM, reset a result, or start model inference.

A legacy observer launched from a sandbox can continue publishing fresh-looking
but restricted probe errors. New startup refuses to mistake its snapshot for a
current verified observer. Running `repair` outside that sandbox replaces it
with a process that can use the host's normal Lima sockets and GitHub broker.
If GitHub authentication is unavailable, repair reports that separately; use
`gh auth login` in the host Terminal if requested by `gh`.

Local builds need no artifact workflow. The dashboard shows CI/CD as unused. A
missing workflow blocks only the optional `github-actions` backend.

```sh
./scripts/gauntlet doctor
./scripts/gauntlet status
./scripts/gauntlet down
```

`doctor` exits 2 for an unavailable VM/GitHub connection or insufficient resource
headroom. `status` reads the operational snapshot. `down` stops the local UI and
observer; it does not kill a potentially active remote benchmark or remove data.

The observer never retries a terminal benchmark failure. Losing observation of
a running/staging job marks it unknown and pauses all further execution. On host
restart the same rule applies.

For a diagnosed and corrected **local build** failure, explicitly use
`./scripts/gauntlet repair --retry-builds`. The command verifies each old VM
receipt reports a terminal build failure, no benchmark-start marker exists, and
the old build container is absent. It creates new job IDs and archives the old
records, retaining their logs. Unknown work and benchmark failures are never
retried by this option. Ordinary `repair` leaves terminal failures unchanged.
New build failures retain their actual log tail privately in
`.gauntlet-ops/private/local-builds/JOB_ID/build-error.log` and publish only a
bounded error summary, failure phase and exit code. The image also checks Python
and Cargo as UID 65532 before it can be used for release compilation.

For a benchmark job that finished in the VM:

```sh
./scripts/gauntlet down
./scripts/gauntlet reconcile EXACT_JOB_ID
./scripts/gauntlet up
```

Reconciliation reads the existing worker receipt and does no inference or replay.
A staging interruption has no benchmark receipt: inspect the retained
`.gauntlet-ops/private/artifacts/SHA/stage.log`, the candidate directory and VM
controls before an explicit operator recovery. Do not clear an unknown job just
to let the queue continue.

`./scripts/gauntlet diagnose` reads the fixed retained VM staging/control records
and saves bounded details into the private host job directory as
`stage-diagnostic.json`. It does not replay work or change queue state. Future
staging failures collect these details automatically, including the control's
error, traceback, SDK stderr and cleanup observations; the public snapshot gets
only a bounded error summary. This collector can diagnose an already-failed job
without upgrading or restarting the VM controller.

After correcting a runner setup error, `./scripts/gauntlet retry-staging JOB_ID`
supports a failed initial boundary conformance control or a dependency-validation
failure before any control began. It stops the observer and checks the Root worker
lease, process identity, successful original build receipt, absence of benchmark
execution, and complete cell/image cleanup.
It retains both VM staging trees under `.failed-JOB_ID`, archives the old job,
and queues a new attempt using the original exact-commit build. It refuses an
active process, deployed candidate, or uncertain cell, MCP, or SDK cleanup. Install
the corrected controller before restarting the observer with `up`. This command
does not automatically retry failures or grant conformance.

The same command can retain a deployed release whose strict benchmark stopped
at the known missing-completion-module preflight. This exception requires matching
Root start/result receipts, the exact deployment and report digests, zero known
model usage, six unexecuted benchmark cells, a dead controller process, complete
staging cleanup, and conformance revalidation under the original controller.
Other benchmark failures and any actual benchmark control execution are refused.
Original results remain retained; the new attempt runs every staging role afresh.

Staging completes all six diagnostic roles (including the five conformance
roles and injection) when each prior role has proven
cell, MCP, SDK, image and profile cleanup. Clean failures produce a retained
`conformance-failed` result and allow the next release tag to be tested. They
never produce a deployment or admit benchmark execution. Uncertain cleanup or
an interrupted operation still pauses the entire queue.

The 3.48.0 and 3.49.0 tags export the native OMP MCP proxy implementation but do
not expose `guard omp-mcp-proxy`. Their version-scoped entry adapter invokes the
installed `RuntimeMcpGuardProxy` API with OMP attribution, normal local/synced
policy loading, and the fixed synthetic upstream. Installed product bytes stay
unchanged. This exercises the library route, and does not claim CLI coverage.
The adapter source is included in fresh conformance source pins.

Cold daemon status queries may use up to 30 seconds within the existing shared
60-second setup deadline. An exhausted setup budget still aborts and cleans the
cell; it does not retry a timed-out RPC or extend the semantic control deadlines.

The `glibc-two-arenas.v1` executor image preserves the existing two-arena malloc
policy even when native children sanitize their environment. A cold v3.49 probe
showed about 996 MiB of native virtual address space against the 1 GiB process
ceiling despite only about 276 MiB peak cell RAM. The image policy reduced native
virtual use to about 199 MiB without raising any limit. The dashboard reports
live product-cell RAM, tasks, native virtual address space and headroom separately
from the VM's 16 GiB allocation.

Bootstrap compiles the small reviewed `malloc_policy.c` as UID 65532 in the pinned
builder, with networking off, then layers the library onto the pinned executor.
The private rootfs accepts only the fixed image-owned preload path. This does not
modify VM-wide loader settings or candidate package bytes. The original image,
baseline assets and results remain retained. A matching cell-artifact manifest
pins the constructor code; new release controls use the new image and artifacts.
The original baseline is verified separately under its original controller.
If a newer candidate needs packages absent from that baseline, provision a
separate, immutable Python dependency prefix and set
`staging_dependency_prefix` and `staging_dependency_prefix_digest` in the private
operator configuration. The digest covers the entire prefix. Root verifies the
original baseline first, then pins the additional prefix only in the new staging
template. This keeps historical conformance evidence tied to its original bytes.

`./scripts/gauntlet probe-runtime JOB_ID --cold-prompt` observes the exact first
prompt in a fresh product cell before any sandbox-planning warm-up. Its private
result includes kernel memory/PID events, process virtual memory, thread counts,
and address-space ceilings. It uses the currently installed diagnostic executor,
records its image ID, and never substitutes for a benchmark control or admission.

These two tags also use a version-scoped adapter for their installed native
`pi-hook-bridge`, the client used by the released OMP extension. The old CLI
fallback discards an OMP containment receipt. The adapter uses the extension's
70% bridge budget and remaining-time metadata, and preserves the native bridge's
response. The bridge owns resident discovery and authenticated HTTP fallback.
It executes inside the isolated product cell; it does not patch the tag or claim
CLI fallback coverage. Guard home and workspace remain fixed. A missing bridge
or invalid response fails closed. An earlier HTTP-only adapter bypassed this
client; its failed observations remain retained as HTTP-path diagnostics.

Both tags lack `guard/runtime/contained_completion.py`, required by the current
strict benchmark profile. Six controls can therefore pass while strict admission
remains blocked. Staging verifies each signed record with the same six-role
validator used by the deterministic benchmark, then records `diagnostic-passed`,
the individual case results, and `contained-output-completion.v1` as missing.
It does not create a deployment or publish a successful PR check. The dashboard
counts diagnostic and benchmark passes separately. No admission floor is removed.
The 3.50.0a5 alpha still exports the MCP proxy library without the corresponding
CLI command, so its exact version uses the same pinned library entry adapter.
The unmodified alpha also lacks the contained-output capability. Its tagged source
declares 3.49.0 until the release workflow stamps 3.50.0a5, so a local candidate
must apply that version stamp before building an alpha-identical package. A
separate patched branch can add the completion capability and run the strict
profile without changing the original release checkout or its diagnostic result.

For a retained deployed candidate that already completed staging,
`./scripts/gauntlet audit-staging JOB_ID` verifies all six signed staging records
without replay. It stops the observer, requires an idle Root worker and a matching
terminal benchmark receipt, and verifies the candidate assets and original
controller's conformance pins. The audit is retained separately; the strict result
is preserved. Restart telemetry and queued work with `./scripts/gauntlet up`.

`./scripts/gauntlet hold` prevents new admissions in the current observer while
active work completes and telemetry continues. `resume` removes the hold; it
does not reset failed jobs. An older observer must first be updated with
`repair --wait-idle`. `repair --no-start` installs and verifies a controller
without restarting the observer, for deliberate maintenance.

`./scripts/gauntlet probe-runtime JOB_ID` diagnoses a cleaned conformance
failure in a fresh isolated product cell under the Root worker lease. It holds
new admissions and separately checks namespaces, overlay filesystem behavior,
native planning, and hook responses. It never grants benchmark admission and
requires verified cleanup. Results remain private in `runtime-probe.json` and
a retained VM probe directory. These diagnostic operations are separate from
the normal benchmark controls.

Only `.gauntlet-ops/public` is mounted into Docker, read-only. Raw evidence and
signing state stay in restricted VM storage; host queue records, artifact
provenance and service logs stay in `.gauntlet-ops/private`. The dashboard binds
to loopback. `public_dashboard_url` is optional and should stay null unless an
authenticated HTTPS frontend is separately deployed.

## Make it required later

Review the additive plan, which makes **no remote change**:

```sh
./scripts/gauntlet gate enable
```

After an actual PR check has passed and its success was published, explicitly
enable it using a credential with repository administration permission:

```sh
./scripts/gauntlet gate enable --apply
```

This creates a separate ruleset named `HOL Gauntlet PR gate`, scoped to `main`,
requiring only `hol-gauntlet/deterministic` and an up-to-date branch. Existing
rulesets, required checks, deployment jobs and branch protection are preserved.
The command refuses an unhealthy worker, unresolved execution, or absence of a
real passing/published PR check. Review repository bypass policy before
activation; no bypass actors are added by this ruleset.

Return only this owned ruleset to passive mode:

```sh
./scripts/gauntlet gate disable --apply
```

If another rule independently requires the same context, disabling the owned
ruleset does not remove that other requirement. Once required, worker downtime
leaves new PRs waiting; keep the worker available or disable the owned gate.

## Verification and current limits

```sh
python3 -B -m unittest tests.test_gauntlet_operations tests.test_gauntlet_recovery tests.test_gauntlet_releases tests.test_gauntlet_local_build tests.test_gauntlet_diagnostics tests.test_gauntlet_network tests.test_gauntlet_resources tests.test_gauntlet_stage_diagnostics -v
node --check ci/gauntlet/control_plane/static/app.js
```

These tests exercise the actual queue/persistence/status state machine, hostile
artifact paths, identity mismatches, interrupted observations, stale telemetry,
real HTTP parsing over an in-memory transport, release allowlisting, annotated
tags, retained queue migration, dispatch deduplication, build identity and
process-identity checks. They also cover additive gate policy. Fake
backend observations prove orchestration, not live Guard security efficacy.

The last host observation reported a running 2-vCPU/8-GiB VM and both selected
release commits resolved. The local-build upgrade preserves those jobs and all
65 archived PR records. Run `./scripts/gauntlet repair` in the normal host
Terminal to install the new build supervisor and restart the observer. This
implementation sandbox cannot access Lima's control socket, so live compilation
and the two end-to-end runs remain unverified. Tests include actual shallow Git
capture/checkout from an offline fixture. No CI/CD publication is required.

API contracts: [commit statuses](https://docs.github.com/en/rest/commits/statuses),
[repository rulesets](https://docs.github.com/en/rest/repos/rules),
[artifact metadata](https://docs.github.com/en/rest/actions/artifacts), and
[hosted ARM runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

### Test a local candidate alongside releases

Use a separate clean checkout on a `codex/gauntlet-` branch. Commit the product changes locally, then run:

```sh
./scripts/gauntlet test-local /absolute/path/to/committed-candidate --native
```

The command stops the idle observer, captures an explicit local candidate identity, then launches the dashboard and resumes observation and admission. Git transfers immutable commit objects; product build hooks and tests execute only in the unprivileged ARM64 VM builder. The builder checks completion contracts and tests the installed wheel with its exact compiled native binary and normal repository fixtures. An artifact is admitted only after those contracts pass. Failed contract runs retain the compiled wheel; `repair --retry-builds` verifies and retests those same compiled bytes without another Rust compilation. Staging checks all six controls; strict admission requires the actual installed completion module, fresh conformance and pinned source/image identities. The worker then runs the strict six-control benchmark. Local candidates never publish GitHub statuses and do not change merge rules. Existing exact-release results remain visible. Changed, dirty, duplicate and unresolved candidates are refused; old evidence is retained.

The VM builder uses a per-job enforcing AppArmor profile derived from the [containers/common v0.57.4 default template](https://github.com/containers/common/blob/v0.57.4/pkg/apparmor/apparmor_linux_template.go). Its proc, sysfs and mount denials remain. Native process identity reads and signals are scoped to that job's own profile and the equivalent stacked `crun` label. Container disappearance and profile removal are checked before a build can be admitted; uncertain cleanup blocks admission. The benchmark's separate product-cell isolation profile is unchanged.
