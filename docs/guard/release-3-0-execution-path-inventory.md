# `release/3.0` execution-path inventory

Status: wave-zero baseline inventory. Audience: execution-assurance implementers and gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

This document is the versioned execution-path matrix for HOL Guard: every distinct path by which Guard intercepts, evaluates, or executes an action, with its entry point, execution owner, failure mode, and actual guarantee.

## Execution paths

| # | Path | Entry point | Execution owner | Failure mode | Actual guarantee |
| --- | --- | --- | --- | --- | --- |
| 1 | Daemon HTTP API | `daemon/server.py` route table (`/v1/*`), e.g. `initialize` `:2231`, `sessions/list` `:2232` | Local daemon process (Guard-owned) | Daemon down → callers fall back per-surface (CLI one-shot, hook direct eval) | Authenticated local decisions when daemon reachable; routes map 1:1 to `runtime/surface_server.py:SERVER_METHODS` |
| 2 | Hook bridge dispatch | `cli/commands_hook_router.py` → per-harness handlers (`commands_hook_codex.py`, `commands_hook_claude.py`, `commands_hook_copilot.py`, `commands_hook_generic.py`) | Hook subprocess (Guard-owned, harness-invoked) | Hook error/timeout → per-adapter behavior; harnesses without enforceable hooks are observe-only | Pre/post-tool interception where the harness protocol supports it |
| 3 | Runtime evaluation pipeline | `runtime/command_evaluation.py:evaluate_command` (`:114`); effect decisions via `runtime/effect_decision.py:evaluate_effect_decision` | Guard evaluation core | Parse uncertainty → fail-closed minimum floor (`review`/`block`); unknown actions normalize to `review` (`action_lattice.py:11-12`) | Deterministic action lattice: `allow < warn < review < require-reapproval < sandbox-required < block` (`action_lattice.py:5`) |
| 4 | CLI wrappers | `hol-guard run <harness>`, `hol-guard protect -- <cmd>` (cli/commands_*.py) | Guard CLI process | Wrapper failure → command not launched (no silent pass-through) | Launch-gate: harness only starts when effective action is not `block` (docs/guard/architecture.md) |
| 5 | Package shims | `guard/shims/` — npm/npx/pnpm/yarn/bun, pip/pip3/pipenv/pipx/poetry/uv/uvx, cargo, go, mvn/gradle, composer, bundle | Shim wrapper process (Guard-owned) | Shim absent → package manager runs unmanaged | Support labels in `docs/guard/testing-matrix.md`: Protected (npm, PyPI), Beta (Cargo/Go/Maven/Composer/RubyGems), Monitor-only (Docker/Actions/system/NuGet) |
| 6 | Containment executor | `runtime/containment_executor.py`, `containment_contract.py`, `containment_health.py`; contained runners: `contained_node_execution.py`, `contained_package_script_execution.py`, `contained_typescript_execution.py`, `contained_workspace_write_execution.py`, `cli/commands_contained_write.py` | Contained subprocess under OS sandbox (Seatbelt on macOS, Bubblewrap on Linux) | Sandbox unavailable → guarantee lowered, action upgraded per lattice (sandbox-required never collapses to review: `action_lattice.py:8-9`) | Filesystem/network/process limits enforced by OS sandbox primitives where available |
| 7 | Restricted analysis sandboxes | `runtime/restricted_pytest*.py`, `runtime/restricted_archive_*.py`, `runtime/offline_archive_sandbox.py`, `runtime/cisco_scan_containment.py` | Guard-owned restricted runner | Restricted runner failure → scan skipped with evidence, never executed outside sandbox | Decode/scan without executing decoded payloads (architecture.md Safe Decode) |
| 8 | Approval center | `runtime/surface_server.py` `approval/*` methods; persistence `store_approvals.py` (`_QUEUE_IDENTITY_VERSION = "v1"`) | Daemon + approval-center UI | Approval daemon unreachable → actions needing approval hold at `review`/`require-reapproval` | Durable approval queue; 30-second transaction-local grants (README) |
| 9 | Cloud sync path | `synced_policy.py` (`cached_policy_bundle_validation`), cloud sync-intel | Local policy cache refreshed from Cloud | Cloud unreachable → last authenticated cached bundle enforced; version downgrades rejected (`bundle_version_downgrade`) | Policy continuity without Cloud availability; v1/v2 bundles dispatched on `contractVersion` |
| 10 | Local dashboard | `dashboard/` served locally | Local daemon + browser | Dashboard down → no enforcement impact (read/approve UI only) | Local-only status/approval surface; not an enforcement boundary |

## Composition invariants

- `sandbox-required` and `require-reapproval` are never lowered by composition rules (`runtime/composition_rules.py:10`). Downgrades exist only for strong false-positive signals and only lower `block → review` or `review → warn` (`composition_rules.py:108-121`); `sandbox-required` is not a downgrade output.
- Unknown action values crossing an untyped boundary normalize to `review` — fail-closed (`action_lattice.py:11-12`).
- Composition never overrides an explicit user policy choice (`composition_rules.py:12`).

## Notes for gate reviewers

- Harness ownership grades are recorded separately in `release-3-0-harness-grades.md`.
- `sandbox-required` consumer semantics are recorded in `release-3-0-sandbox-required-consumers.md`.
- This inventory is descriptive of current behavior; it does not authorize new execution paths.
