# Execution assurance offline provider checklist

Status: required acceptance checklist. Complete every applicable item before release acceptance; record an explicit non-applicable rationale for platform-specific controls.

Use this checklist before accepting evidence from a provider running without continuous Guard Cloud connectivity.

## Host and provider assumptions

- [ ] The host, kernel, hypervisor if used, provider binary, runtime binary, and policy bundle are identified by immutable version and digest.
- [ ] Provider state, bundles, sockets, logs, and temporary files live only under Guard-owned paths with non-shared ownership and fail-closed permissions.
- [ ] The provider has no implicit access to Docker/containerd sockets, metadata endpoints, host credentials, unrelated namespaces, or writable host roots.
- [ ] Required CPU, memory, process, filesystem, namespace, capability, seccomp, and network guarantees are enforced by the selected runtime, not inferred from configuration intent.
- [ ] Unsupported, unknown, or unverifiable controls lower assurance or refuse execution.

## Offline authority

- [ ] The cached policy bundle is signed, unexpired, audience-bound, tenant/workspace/device-bound, versioned, and protected from rollback.
- [ ] The local lease is signed, unexpired, sequence-checked, generation-fenced, and scoped to the exact provider and execution instance.
- [ ] Clock rollback, stale generations, duplicate active leases, and idempotency-key collisions fail closed.
- [ ] Offline execution cannot mint broader authority, extend retention, or convert missing Cloud confirmation into verified assurance.
- [ ] Reconnection reconciles append-only evidence before new remote authority is accepted; forks and conflicting terminal states are quarantined.

## Evidence and privacy

- [ ] Evidence binds policy digest, artifact digest, provider identity, runtime identity, achieved boundary, execution instance, lease generation, and terminal outcome.
- [ ] Attestations verify signature, issuer, audience, subject, tenant, workspace, device, provider, freshness, nonce, policy digest, artifact digest, and revocation state before granting authority or persistence.
- [ ] Receipt lineage is acyclic, single-parent where required, digest-linked, and monotonic across retries, cancellation, cleanup, and terminal transitions.
- [ ] Output capture is hard bounded before allocation; receipts retain only approved digests, byte counts, and redacted diagnostics.
- [ ] Prompts, tool arguments, environment values, credentials, cookies, raw output, and unrestricted host paths are absent from durable evidence and logs.

## Recovery and reconnect

- [ ] Startup reconciliation inventories runtime state before accepting work.
- [ ] Crash, timeout, cancellation, and provider restart force cleanup or produce explicit cleanup-incomplete evidence and quarantine.
- [ ] Cancellation is idempotent and cannot reverse a completed terminal state.
- [ ] Health flapping, provider disappearance, and capacity exhaustion do not create duplicate ownership or orphaned executions.
- [ ] Reconnect retries are bounded and idempotent; acknowledgement cannot erase or rewrite previously committed evidence.

## Verification record

Record the candidate commit, provider/runtime digests, host platform and architecture, policy and lease versions, migration version, feature-flag state, exact commands, CI run URLs, browser viewport, test corpus, pass/fail counts, cleanup inventory and teardown result, and reviewer through the launch runbook's Evidence record. Never record secrets or raw workload content. Portable contract evidence must not be described as native platform certification.
