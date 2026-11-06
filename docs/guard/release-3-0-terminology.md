# `release/3.0` "sandbox" terminology audit

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

Audit of "sandbox" usage across docs and UI, correcting or qualifying misleading uses without breaking public CLI/API compatibility.

## Rule

"Sandbox" is reserved for OS-enforced execution containment (macOS Seatbelt, Linux Bubblewrap) that actually constrains a running process. Anything that inspects without executing, or that is a policy directive rather than a mechanism, must not be called a sandbox unqualified.

## Findings

| Location | Current text | Verdict | Action |
| --- | --- | --- | --- |
| `docs/guard/architecture.md:16` | "a Safe Decode **sandbox** for encoded commands and prompt text" | Misleading: the decode scanner never executes; it is a text pipeline, not a containment mechanism | Corrected to "Safe Decode scanning layer" |
| `docs/guard/local-vs-cloud.md:40` | "Safe Decode runs locally too. It inspects encoded payload layers" | Correct: describes the decode scanner without calling it a sandbox | No change |
| `docs/guard/get-started.md:212,237` | `default_action = "sandbox-required"` | Correct: this is the action-lattice directive, not a component claim | Keep; clarify in a note that it routes to OS containment |
| `docs/guard/harness-support.md:95` | "sandbox `off` as degraded protection states" (Grok config) | Correct: refers to the harness's own sandbox setting surfaced as degraded | Keep |
| `runtime/safe_decode.py` module name | `safe_decode` | Correct: module is named for decoding, not sandboxing | Keep |

## Compatibility

No public CLI flag, API field, or persisted value is renamed. The action-lattice value `sandbox-required` is a public policy contract and is unchanged. Only descriptive prose is corrected; no compatibility alias is required because no identifier changed.

## UI audit

The local dashboard uses "sandbox" only in the context of the action directive and containment status; no UI surface presents the decode scanner as a containment sandbox. No UI copy change required in this baseline.

## Notes

- Reserved-term enforcement: new docs/UI must not call the decode scanner a "sandbox" and must qualify any non-OS "sandbox" use.
- This audit does not rename the `sandbox-required` action value, which is a frozen public contract.
