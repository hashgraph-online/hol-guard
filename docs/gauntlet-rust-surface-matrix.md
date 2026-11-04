# Gauntlet command and state ownership matrix

This is a migration inventory for Python Gauntlet PR #5263 at `b4efd8171b06d0e13cbe12a077c376ecdc891fd1`. It records the CLI and operational surfaces that the Rust port must preserve or explicitly leave as versioned Python readers. It is not evidence that a Rust command exists. The [execution checklist](gauntlet-rust-execution-checklist.md) remains the source of completion status. All external source and asset pins must arrive from outside the candidate build.

## CLI surfaces

| Current entrypoint and commands | Current effect | Proposed Rust owner / phase |
| --- | --- | --- |
| `scripts/gauntlet up`, `down`, `doctor`, `status`, `agent`, `hold`, `resume` | Own the passive dashboard/observer lifecycle, VM readiness and admission hold. | Host controller, Phase 3. |
| `scripts/gauntlet repair`, `diagnose`, `reconcile`, `retry-staging`, `probe-runtime`, `audit-staging` | Repair an idle deployment, inspect retained failures, reconcile exact receipts, reuse a verified build, run bounded diagnostics. | Host controller plus fixed VM worker, Phases 2–3. Recovery must not replay an uncertain job. |
| `scripts/gauntlet test-local`, `features-local` | Queue a clean exact-commit candidate and run source-bound product feature audit. | Host admission plus VM builder/stager, Phases 2–3. |
| `scripts/gauntlet live-local`, `feature-ai-local`, `refresh-live-candidate`, `live-reconcile` | Run 12-cell or two-cell local Qwen E2E, refresh exact deployment, reconcile model/VM outcome. | Host model supervisor and campaign controller, Phases 3–4. |
| `scripts/gauntlet gate enable\|disable` | Print a ruleset plan; `--apply` changes the Gauntlet-owned GitHub ruleset. | Separately reviewed publication controller, Phase 5. Keep inactive throughout migration. |
| `python -m ci.gauntlet.benchmark profile`, `preview`, `deterministic`, `pilot` | Export beta selection, compile inventory, run zero-model controls, or one diagnostic live episode. | Campaign catalog and VM executor, Phases 2–4. |
| `python -m ci.gauntlet.benchmark freeze`, `run`, `status`, `gate` | Freeze selected local campaign, execute, audit retained attempts, compute local verdict. | Campaign controller and verifier, Phase 4. |
| `python -m ci.gauntlet.benchmark ci preflight\|freeze\|run\|resume\|report\|check` | Versioned portable CI path. `check` creates a fresh freeze, executes the complete selected profile and writes a local-integrity report. | Trusted CI runner and evidence verifier, Phases 4–5. Preserve exit/status semantics or version a successor. |
| `python -m ci.gauntlet.benchmark approval`, `developer` | Two-session approval and developer diagnostics. | Campaign controller, Phase 4. |
| `python -m ci.gauntlet list`, `run`, `installed`, `verify`, `pack`, `qualify` | Fixed legacy catalog, real-agent run, installed acceptance, independent evidence verification/export and trusted qualification driver. | Legacy controller/verifier/publisher, Phase 5; retain Python readers for unsupported historical formats. |

The `ci check` profile values are `deterministic`, `beta-e2e`, `feature-ai`, and `feature-ai-protocol`. The legacy `run` profiles are `core`, `contained-bun-vitest`, `full-tasks`, `approval-retry`, and `connector-setup`; only its pinned OMP core path makes the existing qualification claim. The legacy harness values are `omp`, `claude-code`, `codex`, and `cursor`; non-OMP harnesses remain diagnostic. A Rust CLI must not silently collapse these scopes into one green result.

## Versioned inputs and executable boundaries

| Input or external process | Current contract | Rust owner / outstanding proof |
| --- | --- | --- |
| Runner declarations `gauntlet-ci-runner.v1`–`.v7`, 22 Draft 2020-12 schemas | Caller-pinned canonical config, campaign/policy, selected cells, shard and budget checks. | `gauntlet-contracts` and `gauntlet-evidence` have partial read-only parity. Full asset custody and installed identity remain Phase 1. |
| File roles `bun`, `node`, `wheel`, `native`, `policy`, `compiler`, `model_manifest`, `provider_manifest`, optional `conformance` | Exact SHA-256, canonical relative path; executable roles require access to run. | Phase 1 reader has hashes and execute bits; OS access and execution custody remain open. |
| Tree roles `sdk`, optional `zod_cache`, `guard_prefix`; `private_cell` artifact set | Inert tree/manifest digests, ownership, modes, controller source binding, installed runtime metadata. | Phase 1 tree prototype; Root-owned prefix and private-cell parity remain open. |
| Linux ARM `limactl` guest, Podman builder, `slirp4netns`, AppArmor/seccomp, Bubblewrap and native runtime | VM executes candidate build and product cells under restricted identities, not in the Mac host or as Root. | Fixed Rust worker and negative isolation matrix, Phase 2. |
| Bun/Node/OMP SDK and local Qwen/MLX provider | Actual agent/tool traffic, host-owned model process and lifetime quota. | Bounded external adapters supervised by Rust, Phase 4; no scripted inference substitute. |
| Product pytest feature audit | 28 fixed contract groups on the exact wheel/source/native pairing. | Keep pytest as the external executor; Rust must verify its report provenance, Phase 2. |

The VM worker currently accepts only `inspect`, `progress`, `reconcile`, and identity/deployment-bound one-time `run`. The new Rust request and response syntax is specified in [the worker boundary](gauntlet-rust-worker-protocol.md); it does not yet install or dispatch a worker.

## State, public status and receipts

The Python observer stores private job records under `private/jobs/<job-id>.json`. Its operational states include `queued`, `waiting`, `waiting-candidate`, `preparing`, `running`, `unknown`, `passed`, `diagnostic-passed`, `failed`, `build-failed`, `conformance-failed`, `invalid-evidence`, `superseded`, and `archived`. A restart changes `preparing` or `running` to `unknown`; this blocks admission until exact remote receipt reconciliation. Rust must use a new state namespace and prove the same no-replay behavior before cutover.

The public snapshot is `hol-gauntlet-dashboard.v1` with observer `hol-gauntlet-observer.v2`. It exposes only an allowlist of up to 200 unarchived jobs, including identity, state, reason, timestamps, phase/events, bounded progress, selected build/stage summaries and public resource/headroom telemetry. Private logs, credentials, config, candidate runtime state and signing material stay outside this snapshot. Rust dashboard tests must show stale or absent telemetry as unavailable.

The VM uses a Root-owned worker lease and a one-time `<job>.started.json` marker before candidate execution, followed by `<job>.json` terminal receipt. The build/stage paths have their own retained receipts and progress files. The workflow controller uses `ci-controller.lock`, per-shard attempt ledgers and immutable frozen inputs. The host model provider uses `events.jsonl` and `quota.lock`; unsettled or unknown usage halts admission. A new Rust writer must not share Python's live lock/journal namespace, and a reader cannot turn absence of a terminal receipt into permission to retry.

Local control-plane commands return `0` for success and `2` for caught operational errors. `ci check` returns its report's exit code: `0` for accepted local result, `1` for a computed failed gate, `2` for invalid execution, and `130` for interruption. Its report remains `qualification_eligible: false`, `trust_status: local-integrity-only`, and `production_ci_activated: false`. The Python worker also exits `2` on rejected requests. The legacy CLI's full exit-code matrix still needs a separate differential inventory; do not infer it from this row.

## Open inventory work

This table covers the named entrypoints and primary durable state boundaries. The 420-file [parity manifest](../ci/gauntlet-rs/parity-manifest.v1.json) still needs disposition-by-disposition review. In particular, enumerate every historical evidence schema, provider and controller journal format, public status field, external executable argument contract, and legacy exit code against a trusted Rust owner or retained Python reader. The checklist leaves that audit open until the matrix is exhaustive and its accept/refuse cases are frozen.
