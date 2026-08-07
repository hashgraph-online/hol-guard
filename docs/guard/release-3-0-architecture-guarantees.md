# `release/3.0` architecture and guarantee matrix

Status: wave-zero baseline. Audience: execution-assurance implementers and gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

A process/function view of HOL Guard that keeps the five enforcement-adjacent planes distinct — harness hooks, the analysis decode scanner, OS containment, MDM/EDR, and evidence/Cloud — with the guarantee each actually provides.

## Process/function diagram

```
                         ┌──────────────────────────────────────────────┐
                         │                 Harnesses                    │
                         │  Codex Claude Copilot Cursor Gemini Grok ... │
                         └───────┬──────────────────────┬───────────────┘
                    hook invoke  │                      │ launch
                                 ▼                      ▼
        ┌─────────────────────────────┐   ┌────────────────────────────┐
        │  (1) Harness hooks          │   │ (4) CLI wrappers / shims   │
        │  pre/post tool intercept    │   │ hol-guard run / protect    │
        └───────┬─────────────────────┘   └───────┬────────────────────┘
                │ evaluate                        │ launch-gate
                ▼                                 ▼
        ┌────────────────────────────────────────────────────────────┐
        │  (2) Runtime evaluation (action lattice)                   │
        │  command_evaluation → effect_decision → composed action    │
        │  allow<warn<review<require-reapproval<sandbox-required<blk │
        └───────┬───────────────────────────────┬────────────────────┘
                │ decode-only                   │ sandbox-required
                ▼                               ▼
        ┌───────────────────────────┐   ┌────────────────────────────┐
        │ (3) Safe Decode scanner   │   │ (5) OS containment         │
        │ text unwrap, never exec   │   │ Seatbelt / Bubblewrap      │
        └───────────────────────────┘   └───────┬────────────────────┘
                                                │ contained subprocess
                ┌───────────────────────────────┼────────────────────┐
                ▼                               ▼                    ▼
        ┌──────────────────┐        ┌──────────────────┐   ┌──────────────────┐
        │ (6) Evidence     │        │ (7) Approval     │   │ (8) MDM / EDR    │
        │ receipts + store │        │ center queue     │   │ device seams     │
        └───────┬──────────┘        └──────────────────┘   └──────────────────┘
                │ sync (cached, workspace-scoped)
                ▼
        ┌──────────────────┐
        │ (9) Guard Cloud  │  policy distribution, fleet truth (observe-only)
        └──────────────────┘
```

## Plane guarantees

| Plane | Component | Guarantee it provides | Guarantee it does NOT provide |
| --- | --- | --- | --- |
| Harness hooks | `cli/commands_hook_*` | pre/post-tool interception where the harness protocol supports it; fail-closed under strict fail mode | interception on harnesses without an enforceable hook surface |
| Analysis decode scanner | `runtime/safe_decode.py` | bounded text unwrapping of encoded layers; eval/exec signal detection; never executes decoded payloads | execution containment, network/fs control (it is a scanner, not a sandbox) |
| OS containment | `runtime/containment_executor.py` | OS-enforced fs/network/process limits via Seatbelt/Bubblewrap where the backend is available | containment when the backend binary is unavailable (guarantee lowers via the lattice) |
| MDM / EDR | `mdm/`, lifecycle scheduler | device enrollment/touch state, removal seams | local command enforcement |
| Evidence / Cloud | `store/`, `synced_policy.py`, portal routes | durable receipts, cached authenticated policy, workspace-scoped fleet truth | remote workload execution (post-MVP, separately gated) |

## Distinctness assertions (for docs review)

1. Hooks (1), the analysis decode scanner (3), and OS containment (5) are three different things: hooks intercept, the scanner inspects text without executing, containment executes under OS limits. No one substitutes for another.
2. MDM/EDR (8) is a device-identity/enrollment plane, not a command-enforcement plane.
3. Evidence/Cloud (6, 9) is an evidence and policy-distribution plane; Cloud is observe-only for fleet truth and does not execute local workloads.
4. `sandbox-required` (plane 2) routes to OS containment (plane 5) and is never satisfied by the analysis decode scanner (plane 3).

## Terminology (see `release-3-0-terminology.md`)

The word "sandbox" is reserved for OS-enforced execution containment (Seatbelt/Bubblewrap). The decode scanner is not a sandbox: it never executes. `sandbox-required` is an action-lattice directive, not a component name.

## Notes

- This document describes current architecture; it does not authorize new planes or remote execution.
- Containment guarantee detail lives in `release-3-0-containment-baseline.md`; execution paths in `release-3-0-execution-path-inventory.md`.
