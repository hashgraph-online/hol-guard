# `release/3.0` threat-boundary matrix (G0 security gate)

Status: wave-zero security gate sign-off. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

This matrix adjudicates the wave-zero baseline before any schema implementation. It rejects missing execution paths, inflated guarantees, and unverified provider assumptions, and fixes the trust boundary for each plane. Evidence: `release-3-0-execution-path-inventory.md`, `release-3-0-harness-grades.md`, `release-3-0-sandbox-required-consumers.md`, `release-3-0-containment-baseline.md`, `release-3-0-architecture-guarantees.md`, `release-3-0-compatibility-evidence.md`, `release-3-0-main-compatibility.md`.

## Trust boundaries

| Boundary | Crosses | Guard side | Untrusted side | Guarantee at boundary |
| --- | --- | --- | --- | --- |
| Hook invocation | harness → Guard | hook subprocess evaluation | harness process, tool args | fail-closed under strict fail mode; unknown actions → review |
| Evaluation core | Guard internal | action lattice composition | raw command text | `sandbox-required`/`require-reapproval` never lowered; unknown → review |
| OS containment | Guard → contained process | Seatbelt/Bubblewrap backend | contained subprocess | OS-enforced fs/network/process limits where backend available |
| Approval | action → user | approval center queue | requester | 30-second transaction-local grant; not auto-approvable |
| Policy sync | Cloud → local | cached authenticated bundle | Cloud payload | signature + version-downgrade rejection; v1/v2 dispatch on contractVersion |
| Cloud fleet truth | local → Cloud | workspace-scoped actor | Cloud consumers | observe-only; no remote execution |
| Decode scanning | encoded payload → reviewer | safe_decode text pipeline | decoded content | never executes decoded payloads; size/depth/time bounded |

## Missing paths (rejected as blocking or accepted as alpha limitation)

- Remote workload execution/grants: absent by design. This is a post-MVP, separately gated capability (Phase 3) and is not required for the 3.0 local MVP. Accepted as out of scope, not a gap.
- VS Code Copilot extension-host interception: not supported. Only the `copilot` CLI wrapper and repo-local hooks are boundaries. Accepted alpha limitation.
- Harnesses graded `observe_only_degraded` (Pi, OpenCode, Antigravity) and `host_decision_only` (Gemini, Grok, Kimi, ZCode, and Hermes/OpenClaw on the unmanaged path) cannot satisfy mandatory assurance. Accepted alpha limitation, explicitly graded in `release-3-0-harness-grades.md`.
- No runtime Docker isolation backend exists. Docker references are classification rules, not an isolation mechanism. Not claimed as a guarantee.

## Inflated guarantees (rejected)

- The analysis decode scanner is not a sandbox. It never executes; calling it one was misleading and is corrected (`release-3-0-terminology.md`). It provides inspection, not containment.
- `sandbox-required` is an action-lattice directive routed to OS containment; it is not satisfied by the decode scanner or by observe-only harnesses.
- Approval-center `approval_tier` does not by itself imply local execution ownership; harness grades are derived from the hook surface, not the tier label.
- The forward-merge compatibility strategy is not a compatibility adapter; compatibility is proven by the v1 policy parser dispatch and byte-identical receipt/session/protection stores, not by the merge.

## Unverified provider assumptions (rejected)

- No execution provider (OCI/gVisor/Kata/KVM) is assumed or required for the 3.0 local MVP. Seatbelt/Bubblewrap is the reference local containment. Provider selection and attestation are post-MVP and separately gated.
- Containment guarantee cells are marked "not enforced" rather than inferred where a backend does not enforce a control (`release-3-0-containment-baseline.md`).
- Cloud never emits an isolation requirement to a client that did not advertise the compatible 3.0 contract version.

## Adjudication

Wave-zero baseline is accepted for contract-freeze work to proceed, subject to the accepted alpha limitations above (degraded/host-decision harnesses, no VS Code extension interception, no Docker isolation backend). No blocking missing path, inflated guarantee, or unverified provider assumption remains unresolved. The signed-off matrix is this document.

Sign-off: SOL-MEDIUM (self-approved under owner-override). Independent review requested on the integrating PR.

No release, publication, deployment, or policy activation is authorized by this document.
