# Wave-one contract freeze: abuse-case review (G1 gate)

Status: G1 gate review of `release-3-0-contract-freeze.md`. Scope: adversarial review of each frozen contract against the program's required abuse cases. Reviewer: SOL-MEDIUM under owner-override (independent-pass replay). Source evidence snapshot: `origin/release/3.1` at `97e2408a629acd4946db0677abd4022027d421f4`; release identity migrated to 3.0 and revalidated in PR #1901.

Method: for each required abuse case, identify the frozen clause that must defeat it. Where no clause defeats it, record a blocking finding with the contract amendment that resolves it. Findings are resolved by amending the freeze spec before the gate passes; the generator is not the only reviewer because each amendment is independently checked against the invariant it must preserve.

## Abuse-case → contract mapping

| # | Abuse case | Defeating clause | Verdict |
| --- | --- | --- | --- |
| 1 | Workspace config points Guard at an attacker-controlled provider binary/socket | the provider contract: provider config is Guard/admin-owned, not repository-owned; identity-pinned binaries/sockets | Covered |
| 2 | Provider claims a higher boundary than it enforces | the assurance-levels and atomic-guarantee sections: providers never self-label an arbitrary level; Guard derives max level from declared+verified atomic guarantees; `GuardExecutionAttestationTrust` starts `unattested` | Covered |
| 3 | Attestation replayed from another workspace/device/tenant | the attestation-statement section: schema/signature/freshness/nonce/subject/audience/workspace/policy bindings must verify | Covered |
| 4 | Health succeeds, provider changes, then execution occurs | the provider contract + the fenced-retry section: launch binds provider instance/key thumbprint + monotonic generation + plan digest; replacement or generation drift invalidates the launch | Covered |
| 5 | Required provider fails; code attempts host fallback | the fail-and-recovery matrix: mandatory assurance never silently downgrades to host execution; no fallback below a mandatory policy floor | Covered |
| 6 | Benign action spammed with approvals because optional health is unavailable | the fail-and-recovery matrix: optional route falls back only to an explicitly policy-approved lower route with a visible degraded receipt; health cache uses freshness + stale-while-reverify | Covered |
| 7 | Provider mounts `.env`, `.ssh`, Guard state, VCS metadata, or host sockets | the fenced-retry section and the atomic-guarantee schema: immutable input manifest; secret delivery uses mount/descriptor semantics with no ambient env inheritance; `secret` guarantee enforced | Partially covered — see F1 |
| 8 | Secret values enter context, logs, trace baggage, or Cloud evidence | the security-objectives section objective 4 + the execution-context schema forbidden fields + the privacy contract serialization denylist | Covered |
| 9 | Output truncation hides secret or policy-relevant content | the attestation-statement section: terminal statement binds truncation flags + full-stream byte counts/digests; unscanned tail never implicitly allowed | Covered |
| 10 | Cancellation leaves a process/VM/mount/network rule/secret alive | the fail-and-recovery matrix: cleanup retries independently, surfaces orphan incidents, revokes/zeroizes secrets on terminal or orphan handling | Covered |
| 11 | Retry executes a remote mutation twice | the fenced-retry section: idempotency keyed on attempt nonce; at-most-one provider launch; no changed/unfenced retry after `unknown_outcome` | Covered |
| 12 | Old policy/provider capability restores after revocation | the trust-and-rotation section: downgrade prevention + revocation; the fenced-retry section: capability loss invalidates cached eligibility immediately | Covered |
| 13 | Clock skew extends stale health or attestation validity | the attestation-statement section: freshness binding; the fail-and-recovery matrix: cached health expires quickly enough to prevent stale assurance | Partially covered — see F2 |
| 14 | Root/admin deletes Guard and forges local health | the security-objectives section attacker model: explicitly out of scope (fully privileged local adversary) | Accepted non-goal |
| 15 | Provider capacity exhaustion becomes a broad fail-open | the fail-and-recovery matrix: no silent downgrade; mandatory floor holds; degraded only via policy-approved lower route with receipt | Covered |
| 16 | Environment materializer executes activation hooks during inspection | the provider contract: discovery/health never executes workspace-controlled code; plan is pure/side-effect-free | Covered |
| 17 | OCI image tag changes under the same human-readable name | the provider contract and the trust-and-rotation section: binaries/images identity-pinned by digest, not tag | Covered |
| 18 | RuntimeClass name maps to a weaker handler than policy expects | the resolver semantics: resolver never selects a boundary weaker than the policy-required floor; provenance recorded | Covered |

## Blocking findings and resolutions

### F1 — Abuse case 7: forbidden host mounts

The freeze spec states secrets use mount/descriptor semantics and an immutable input manifest, but does not explicitly enumerate the forbidden host-mount set or state that the provider contract must reject a plan requesting one.

Resolution (amend the provider contract and the fenced-retry section): the provider contract's `plan` validation must reject any input manifest or mount request that targets `.env`, `.ssh`, Guard state directories, VCS metadata, or host sockets (Docker/container control sockets). The `secret` atomic guarantee includes a forbidden-host-path denylist enforced at plan validation, not merely at runtime. This closes the mount-abuse path at the contract's trusted planning boundary rather than trusting the provider to refuse it.

### F2 — Abuse case 13: clock skew and staleness bounds

The freeze spec requires freshness binding and quick-expiring cached health but does not bound clock skew or define the staleness window.

Resolution (amend the attestation-statement section and the fail-and-recovery matrix): attestation and health freshness use a bounded validity window with an explicit maximum accepted clock skew; a provider or attestation whose not-before/not-after window, combined with the accepted skew, exceeds the freshness bound is treated as stale and rejected. Cached health carries a `verified_at` timestamp and a hard expiry; the expiry is short enough to prevent stale assurance yet does not force a network round trip per benign local action (stale-while-reverify only for optional routes).

## Amended clauses (applied to `release-3-0-contract-freeze.md`)

- the provider contract gains: `plan` rejects any input manifest or mount targeting the forbidden host set (`.env`, `.ssh`, Guard state, VCS metadata, host sockets).
- the fenced-retry section gains: the immutable input manifest and secret-delivery lease enforce the same forbidden-host denylist.
- the attestation-statement section gains: freshness uses a bounded validity window with a defined maximum clock skew; out-of-window attestations are stale and rejected.
- the fail-and-recovery matrix gains: cached health carries `verified_at` + hard expiry; stale-while-reverify is allowed only for optional routes.

## Adjudication

With F1 and F2 amended into the freeze spec, every required abuse case is defeated by an explicit contract clause or accepted as a documented non-goal (root/admin adversary). No blocking finding remains open. The contract set is approved for wave-two implementation, subject to the freeze conditions (alpha-versioned, capability-negotiated, fail-closed unknown fields, one shared contract source).

No release, publication, deployment, or policy activation is authorized by this document.
