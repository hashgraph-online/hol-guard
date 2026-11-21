# Native runtime SLO proof

`scripts/bench_guard_native_installed_slo.py` measures the installed daemon
adapter through its hook ingress to the harness decision. It uses the declared
installed route matrix (13 harnesses and 21 PreToolUse/PostToolUse routes),
synthetic safe fixtures, and bounded aggregate output. It never writes command
text, prompts, tool output, paths, tokens, or response bodies to evidence.

There are two deliberately separate performance boundaries. The direct Rust
release gate (`scripts/bench_guard_native_release_gate.py`) keeps the native
runtime limits at warm p95 at most 20 ms, cold one-shot p95 at most 150 ms,
readiness at most 400 ms, and measurable direct c16 p99 at most 100 ms. These
limits exclude the Python adapter and HTTP scheduling overhead.

The installed proof measures the complete adapter-to-decision path. Its
ordinary warm, size-class, resident-recovery, and c16 p99 limit is the existing
production `HOOK_ENGINE_NORMAL_BUDGET_MS` of 1,000 ms; the installed cold
one-shot and readiness checks retain the direct 150 ms and 400 ms limits. c16
must complete resident allowed decisions with zero errors within that adapter
budget. c64 has no latency ceiling: every result must be either a resident
allowed decision or an explicitly classified bounded capacity/overload
response, with zero request errors and no hang.

Each resident-recovery sample first proves a resident allow decision, then
requires the Rust stop command to verify containment of that resident. The
installed adapter's persistent Rust client streams remain alive, matching a
resident restart in production: their next request re-discovers and
authenticates the new resident generation. The complete next adapter request
is timed against the unchanged 1,000 ms budget. Cold one-shot probes and final
session cleanup retain full client teardown. Aggregate per-sample diagnostics
report both adapter time and the enclosing measurement time.

The c16 latency proof uses a dedicated, fully started 16-thread client executor
so thread creation and a larger benchmark-only client pool cannot distort the
production contention being measured. RSS is evaluated separately after c16.
The proof fills the resident worker pool, fully starts the bounded 64-thread c64
load executor, and only then samples the RSS baseline. That same c64 executor
remains alive through the RSS baseline and c64 wave, so client thread allocation
cannot be misreported as daemon/runtime growth. Adapter transport requests are
individually bounded at five seconds and concurrent waves have a six-second
executor envelope; a wave that escapes that bound fails closed without waiting
for executor teardown. The baseline requires three consecutive samples within
a 2 percent RSS plateau and a 30-second deadline; the post-c64 peak is compared
against that steady-state baseline. The resident growth gate remains at most
12 percent.

The nightly native workflow runs the no-environment installed-wheel probe and enforces the
adapter SLO. Windows remains outside this wave. The stress script exposes
bounded thread, descriptor, and RSS aggregates. CI runs its `--enforce-soak`
profile for 100,000 requests over a populated 250,000-receipt store; local
checks use a small request count.

Example proof after installing a version-matched native wheel:

```sh
runtime=$(uv run --no-sync python -c 'from codex_plugin_scanner.guard.native_runtime import native_runtime_status; status = native_runtime_status(); assert status.identity is not None; print(status.identity.path)')
uv run --no-sync python scripts/bench_guard_native_installed_slo.py \
  --runtime "$runtime" \
  --warm-iterations 2 --cold-iterations 2 --recovery-iterations 2 \
  --readiness-samples 2 --enforce
```

Aggregate JSON is bounded by `scripts/native_slo_contract.py`; the contract
sanitizer is tested independently and is applied immediately before printing
or writing evidence. Expected policy denials from large source-reference and
bounded-capacity probes remain visible as `security_denials` and
`security_denials_by_size`; they do not enter the ordinary warm fail-safe
numerator.

## Matched warm-path latency baseline

The SLO proof above gates absolute ceilings at the adapter-to-decision
boundary. It does not compare revisions. The `Warm-path latency baseline`
workflow (`workflow_dispatch`, measurement only, no threshold or gate) answers a
different question: how much faster or slower is the installed product on the
user-visible path between two revisions?

It builds each revision's static Linux native wheel with the nightly
`linux-build` recipe, installs both into separate environments on one hosted
runner, and drives only the public command line, so the identical probe code
runs against either revision:

- Warm hook: install the Claude Code hooks into a throwaway home, then spawn the
  installed `PreToolUse` handler for a benign Bash payload and time spawn to exit.
- Warm non-package `tools/call`: install the Codex MCP proxy around a stdlib
  canary server, keep one session open, and time each `safe_echo` round trip.

Method and noise rules: targets alternate order every round, each round uses a
fresh Guard home and daemon plus discarded warm-up calls, and the headline
percentile is the median across rounds (default five) of each round's p95, with
p50 and p99 reported alongside. A run is flagged noisy when per-round p95 values
span more than 15 percent of their median, and flagged non-comparable when the
decision classes of the timed cohorts differ. Client and service CPU, service
RSS, descriptors and process counts are recorded per call. A bare interpreter
spawn is timed every round as a same-runner drift indicator.

Do not subtract these numbers from the direct release-gate or installed SLO
numbers: they measure different boundaries and must not be reported as a
migration speedup.
