# Native runtime performance evidence

The benchmark scripts emit synthetic, aggregate evidence. A passing short CI
run is **smoke evidence**, not release qualification or a measured production
latency guarantee. Reports never contain commands, prompts, tool output,
private paths, credentials, or response bodies.

## Timing boundaries

| Boundary | Starts | Ends | Current measurement |
| --- | --- | --- | --- |
| `KERNEL` | Typed inputs ready for a single computation | Computation completes | Not measured by these Python scripts |
| `NATIVE_CLIENT` | Python native adapter or persistent client call | Native response returned | Release-gate warm adapter and separate authenticated-client diagnostic |
| `DAEMON_INGRESS` | Normalized request transport call | Harness response decoded | Installed SLO warm, sizes and concurrent waves |
| `INSTALLED_LAUNCHER` | Registered executable/argv invocation | Stdout captured and process exit observed | Claude Code PostToolUse registered-command pilot |

The ordinary native daemon request calls `HookWorker` directly and reuses
persistent Rust client helpers. The release benchmark warm adapter timer starts
at `review_post_tool_native`; it includes Python native-adapter work, runtime
identity verification and the native request. It excludes daemon HTTP ingress
and launcher startup. Its diagnostic now calls the installed production
`native_resident_client_request`, instead of the old Python resident transport
excluded from wheels.

The installed SLO's declared all-harness route corpus still probes production
transport functions using normalized HTTP payloads. That provides route
coverage; it does not establish process-startup latency for every harness or
alias. `--launcher-iterations` adds an independent Claude Code measurement:
install the adapter into a private temporary home, read the command and args
back from its settings, and execute that exact argv. It includes interpreter
startup, stdin, transport, response stdout and exit status. The launcher must
return the expected benign and synthetic credential results through native
resident authority. The report explicitly marks the remaining launchers as
unmeasured. Setting `--launcher-iterations 0` explicitly skips this pilot.

## Semantic reference and existing gates

The old release reference set `HOL_GUARD_NATIVE=off` and only checked that a
worker returned a payload. Current production off mode returns an availability
response, so historical relative-speedup evidence from that reference does not
prove semantic equivalence.

The repaired reference starts a scripts-only child process that explicitly
constructs the retained Python `HookReviewEngine`. Production does not import
this module, install a callback, or enable an environment-controlled semantic
fallback. Both arms must allow a benign fixture with `output_scan_allow` and
block a generated credential with `output_secret_match`. Route, decision and
model-output action must match. Availability responses, unexpected exceptions,
and a block caused by the wrong reason fail validation. Timed benign samples
vary their synthetic marker. The reference is labeled an isolated semantic
engine process; its cold comparison is not a measurement of the historical
multi-process guardian/evaluator topology.

`bench_guard_native_release_gate.py --enforce` retains its existing acceptance
logic:

- Warm native-client p95 **≤20 ms OR ≥1.15×** the isolated Python reference.
- Cold native one-shot p95 **≤150 ms AND ≥5×** the isolated Python reference.
- Native readiness **≤400 ms**, starting after durable snapshot materialization.
  Complete daemon startup is a different measurement.

There is currently no direct-native c16 runner in this release script. The
100 ms direct-concurrency constant is a declared target, not an enforced or
measured direct c16 result. The installed normalized daemon-ingress gates use
the existing 1,000 ms `HOOK_ENGINE_NORMAL_BUDGET_MS` for ordinary warm,
size-class, recovery and c16 p99. Those are legacy regression ceilings, not the
PRD's proposed tighter installed-launcher acceptance targets. c16 requires
resident allowed decisions and zero errors. c64 has no latency ceiling;
responses must be resident decisions or explicit bounded overload outcomes,
with zero request errors and no hang.

Reports retain pooled aggregates for compatibility and also report warm
latency separately for every harness/event route. All these short runs remain
`evidence_class: smoke` and `qualification_complete: false`, regardless of a
passing legacy gate. Increasing one iteration argument alone does not qualify
the complete PRD platform, workload, fault and paired-artifact matrix.

## Capacity and resource scope

The normalized c16 wave uses a prestarted 16-thread executor. The c64 executor
is also fully started before the RSS baseline, remains alive during the wave,
and has bounded requests. The baseline requires three consecutive samples
within a 2 percent plateau and a 30-second deadline. Post-wave growth remains
limited to 12 percent. Requests have five-second transport bounds and a
six-second concurrent-wave envelope.

The legacy short-wave RSS helper measures descendants where available, but its
thread and descriptor helpers measure only the root process. The paired runner
below adds independent daemon-tree memory/CPU/thread/descriptor measurements,
offered arrivals and diagnostic phase spans; those results have their own
scope and do not change the legacy growth limits.
The longer soak has a distinct 50 percent growth limit and seeds legacy receipt
rows; it does not prove sustained ingestion of native decision receipts.

Native wheel CI's small sample counts remain smoke checks. Windows functional
wheel coverage does not establish the omitted Windows installed performance
wave. Release qualification must use the PRD sample minima on each supported
platform and hardware class, alternate baseline/candidate blocks, account for
every attempted request, report per-route confidence intervals and retain
artifact/toolchain identity. Missing routes and measurements block their
acceptance claims; they cannot be inferred from a faster microbenchmark.

## Running smoke checks

After installing a version-matched native wheel, use its interpreter and runtime
with the checked-in benchmark scripts:

```sh
python scripts/bench_guard_native_release_gate.py \
  --runtime /absolute/path/to/guard-runtime --warm-iterations 100 \
  --cold-iterations 3 --enforce
python scripts/bench_guard_native_installed_slo.py \
  --runtime /absolute/path/to/guard-runtime --warm-iterations 2 \
  --cold-iterations 2 --recovery-iterations 2 --readiness-samples 2 \
  --launcher-iterations 2 --enforce
```

Use a real installed wheel for artifact evidence. An editable checkout is
useful for tests but is not installed-artifact qualification. The installed
report is sanitized by `scripts/native_slo_contract.py` before printing or
writing. Expected policy denials remain distinct from native availability and
safe-failure outcomes.

## Paired installed-artifact experiments

`qualify_guard_native.py` runs the same checked-in measurement code using two
separate installed-wheel interpreters. It alternates baseline/candidate and
candidate/baseline order across independent blocks. Qualification sampling
requires at least five runs, distributes at least 10,000 priority samples and
1,000 remaining-route samples across them, and collects at least 100 cold
native invocations and 100 independent recoveries. The priority warm routes
are Claude Code and Codex daemon ingress and the four actual registered
PreToolUse/PostToolUse launchers. Each registered route receives c1 and c16
series plus 100 fresh-launcher starts across the five blocks. The daemon and
resident remain prepared for these launcher starts; resident recovery and cold
Rust one-shot invocation have independent series. Actual observed counts are gated; requested counts
alone cannot pass.

```sh
python scripts/qualify_guard_native.py \
  --baseline-python /absolute/baseline-env/bin/python \
  --candidate-python /absolute/candidate-env/bin/python \
  --baseline-artifact /absolute/baseline-native.whl \
  --candidate-artifact /absolute/candidate-native.whl \
  --mode qualification --runs 5 --output-dir native-qualification
```

Both wheels are required in qualification mode. Their SHA-256 values are
recorded, and the worker's installed package files must match the corresponding
wheel's package-content digest. Python bytecode and installer-specific metadata
are excluded from that content comparison. Editable installs, mismatched wheel
contents, changed runtime/package digests between blocks, changed hardware or
different corpus definitions reject the comparison. Identical interpreter
binaries in separate virtual environments are supported.

Numeric observations are retained under `private_samples/` with restricted file
permissions. Only `aggregate/` is intended for publishing. Each block includes
per-route nearest-rank quantiles with empirical-bootstrap intervals; the
comparison resamples paired run-level p95/p99 ratios to preserve block pairing.
The report identifies the estimator and 2,000 bootstrap replications. It does
not pool different harnesses or timing boundaries. These confidence intervals
and sample gates are evidence for the measured scope, not proof that every
platform or failure mode has been covered.

The worker also records c1/c4/c16/c64 closed-loop waves and an offered-rate
experiment at each concurrency. Offered arrivals are scheduled independently
of completion. A bounded generator queue records dropped arrivals explicitly;
completed, failed, timed-out and generator-dropped counts must account for all
attempts. Queue and total latency start at the scheduled arrival. A hung
observer fails shutdown accounting instead of blocking the report forever.
Single-wave concurrency tails are explicitly unqualified.

The paired daemon fixture starts a separate installed interpreter before the
full-startup timer ends, then runs the production daemon, helper and resident.
The client sends actual authenticated HTTP hook requests. Its private control
pipe carries readiness and bounded counters outside request timers. Resource
samples target the daemon process and descendants, excluding the benchmark
client. The small fixture control loop is included and disclosed.

Fixture startup has a fixed 30-second control deadline. Progress identifies
workspace creation, store construction, daemon construction, and workspace
registration without extending that deadline. A one-shot diagnostic captures
at most eight shipped source locations if construction remains blocked after
20 seconds; it never captures frame locals, absolute paths, or response data.
The diagnostic timer is cancelled before readiness and hook measurements;
its setup and cleanup are included in full fixture startup. Failed paired
blocks save and print the same sanitized evidence object, including any bounded
startup stack, while raw child output stays private. The native readiness
barrier remains 400 ms.

The development-only pinned psutil collector records RSS, private memory (USS),
CPU, processes and threads on supported systems. Unix file descriptors and
Windows handles are separate fields. Unavailable or permission-denied metrics
are null with explicit reasons; an unavailable USS value cannot become zero.
PID and creation time checks reject unstable inventories. Linux CPU also uses
live and waited-for child counters from /proc. On other systems, observed
exited-child CPU is retained by identity, but children that start and exit
between polls cannot be claimed as fully accounted. Such CPU comparisons stay
unqualified while independently measured memory and latency can qualify.

Concurrent hooks use exact route-count conservation for the whole isolated
batch. Per-request before/after counters overlap under concurrency and cannot
prove each request's route. A successful benign batch is attributed only after
native-resident counts equal delivered allows. Overload, engine bypass, errors,
drops and timeouts stay distinct. Resource samples cover both warm serial
requests and the separate concurrent/offered-load window.

The frozen corpus executes through real private daemon sessions before timing.
It covers 386 semantic and fault fixtures, plus malformed JSON and UTF-8 HTTP
rejections. Each result requires its delivered projection, native projection
when applicable, HTTP status, exact route count and observed setup prerequisites.
Watch/allow configurations are materialized before GuardStore construction.
Transport and approval write faults are injected only at their named boundary;
they do not claim a process crash. Expiry uses an actually acknowledged signed
short-lived generation, waits for wall-clock expiry and requires the resident's
explicit `snapshot_expired` rejection. Standalone generation revocation remains
unqualified because the pinned baseline has no such operation.

An opt-in phase pass runs after uninstrumented headline samples. It records
foreground inclusive spans for executable identity (including hashing), config
lookup, envelope encoding, admission/queue acquisition, native client calls,
activity/receipt submission and response encoding/writing. It never records
arguments, result bodies or exceptions. Nested inclusive spans must not be
summed. This pass does not isolate SHA-256 from filesystem validation, pure
queue wait from admission, or Rust connection/evaluation from the native client
call; those fields are explicitly unmeasured.

The aggregate contains a separate acceptance result for every measured scope.
Native warm p95 is capped at 20 ms, native cold p95 at 150 ms, readiness at
400 ms, and installed launcher c1 p95/p99 at 50/100 ms and c16 p99 at 200 ms.
Product ceilings use each run's upper bootstrap bound; a fast different route
cannot hide a slow route. Migration benefit uses paired intervals with the
original 30 percent gain and 5 percent limit on regression in the other primary
metric. A missing or partially accounted metric cannot pass that comparison.

`qualification_complete` refers only to the declared single-platform measured
scopes; `program_qualification_complete` remains false until other platforms,
nonpriority registered launchers, revocation and native inner-phase evidence
are supplied. Every scope has its own qualified flag, including when another
metric is unavailable. `sampling_passed` is a count/resource check. A zero exit
status means the experiment completed and produced evidence; it does not mean
all product ceilings or migration benefit passed. The existing legacy SLO
checks remain independently enforced by the separate smoke runner.

The `native-performance-qualification.yml` workflow builds baseline commit
`2e672d2d950c6ec471005ddba46e49bba16dc23b` and the exact candidate head into
separate native-wheel environments. It runs Linux x64, macOS x64, macOS arm64
and Windows x64. Ordinary pull requests run smoke. A same-repository pull
request labeled `rust-performance-qualification` runs full qualification before
merge; manual dispatch and the scheduled release branch run also support full
sampling. Fork pull requests retain smoke/read-only permissions. Only bounded
aggregate JSON and build identity are uploaded, never private observations.
