# Wave-five follow-on decision gates — records

Status: decisions recorded. Audience: gate reviewers. Date: 2026-08-01. These are the follow-on gate-class tasks of the reference-runtime wave. Each records a defer/define decision with evidence; none is an alpha blocker, and none authorizes implementation, release, or deployment.

## MicroVM adapter (define) — DEFER

**Question.** Specify a KVM/Firecracker MicroVM adapter (trust, jailer, kernel/rootfs, device model, networking, secrets, attestation, cleanup).

**Decision.** DEFER pending an approved threat model. The wave-five scope selects ONE reference runtime for 3.0 alpha: pinned gVisor `runsc` with `systrap`, reached directly or through the OCI/Kubernetes RuntimeClass path. A MicroVM adapter is a separate, larger trust surface (jailer confinement, kernel/rootfs provenance, device model, KVM-specific attestation) that requires its own approved threat model before any specification or implementation. No MicroVM adapter is specified or implemented. Re-open only with an approved MicroVM threat model.

## Windows isolation research spike (define) — DEFER (go/no-go before code)

**Question.** Evaluate supported Windows isolation primitives without promising parity.

**Decision.** DEFER pending a written threat model and an explicit go/no-go gate. The 3.0 alpha reference runtime targets Linux with pinned gVisor `runsc`; OCI and Kubernetes RuntimeClass provide the plan and orchestration boundaries. Windows isolation primitives (e.g. job objects, silos, Hyper-V containers, restricted tokens) differ substantially and must be evaluated in a dedicated threat model with a go/no-go decision before any code. No Windows isolation code is written and no parity is promised.

## Environment materializer (define) — DEFER

**Question.** Add a separate provenance/reproducibility contract (an environment materializer that can produce a declared execution environment).

**Decision.** DEFER. A materializer must not grant assurance and must not execute activation during inspection. The 3.0 alpha scope has no customer-proven requirement for a materializer distinct from the isolation-provider plan boundary; the reference-runtime path already constrains the execution environment through the provider plan. A materializer would add a new provenance/reproducibility trust surface with no current alpha need. Re-open only with an approved provenance contract and demonstrated demand.

## Optional materializer adapter (decide) — DEFER

**Question.** Decide whether to build an optional materializer adapter after customer-demand and maintenance review.

**Decision.** DEFER (a valid outcome per the gate). No customer demand is established and the maintenance burden of an additional adapter is not justified for 3.0 alpha. If re-opened and approved, it would require synthetic provenance tests and isolation-separation assertions proving it cannot grant assurance or execute activation during inspection. Deferred; does not block alpha.

## Customer remote runner seam (implement) — GATED by the remote execution grant gate

**Question.** Add a provider-neutral authenticated grant-claim/execution/attestation/cancellation/cleanup/result protocol without turning the Guard administration command queue into a workload orchestrator.

**Decision.** GATED — defer to the remote execution grant gate (see `docs/guard/remote-execution-grant-gate.md` on the portal). That gate already decided DEFER: no concrete customer runner is selected and no approved follow-on threat model exists. The remote runner seam is not implemented. If the grant gate re-opens with an approved threat model and a selected runner, this seam would be split into transport/auth, claim-lifecycle, result/cancel, and reconciliation PRs.

---

No release, publication, deployment, remote privileged installation, or adapter implementation is authorized by these records. Deferred adapters do not block the 3.0 alpha.
