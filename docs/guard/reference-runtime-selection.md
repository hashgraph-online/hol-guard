# Reference runtime selection — gVisor

Status: selected for the Guard 3.0 alpha reference path. Audience: gate reviewers and provider maintainers. Date: 2026-08-01.

## Decision

Guard selects **gVisor `runsc` with the `systrap` platform** as the single Linux reference runtime for the 3.0 alpha assurance gate. Kubernetes `RuntimeClass` remains the orchestration adapter and the OCI adapter remains the plan/evidence boundary; neither is itself the selected runtime.

This decision authorizes validation of the pinned reference path. It does not authorize release, deployment, privileged installation, or a production feature flag.

## Selection basis

The selected release is `release-20260727.0`. Guard pins the release URL and SHA-512 digest, copies the verified binary into a Guard-owned path, verifies its exact SHA-256 digest before every run and cancellation operation, and refuses binaries that cannot be re-executed by the sandbox process or are writable outside their owner.

The reference runner:

- forces `--network none` and `--platform systrap`;
- accepts only Guard-owned state and OCI bundle paths;
- requires a read-only root filesystem and bounded CPU, memory, and process limits in the validated corpus;
- exposes only digests and byte counts for bounded stdout/stderr captures;
- force-deletes runtime state after success, runtime failure, timeout, and cancellation;
- treats missing or mismatched binary provenance as a terminal provider error.

The real Linux gate downloads the pinned binary, verifies SHA-512 before execution, and runs an OCI isolation corpus covering read-only-root escape, host-secret and Docker-socket absence, denied mount privilege, denied metadata-network access, crash cleanup, and timeout cleanup. The passing evidence is [Guard gVisor reference runtime run 30702481974](https://github.com/hashgraph-online/hol-guard/actions/runs/30702481974).

## Trust boundary and limitations

gVisor reduces direct host-kernel syscall exposure by interposing its user-space kernel. It does not remove the host kernel, `runsc` binary, Guard provider process, OCI bundle provenance, cgroup implementation, or host filesystem permissions from the trusted computing base. The alpha gate validates `systrap`; it does not claim evidence for gVisor KVM mode. Runtime evidence cannot exceed the guarantees actually observed by the OCI and Kubernetes adapters.

## Alternate runtime characterization — Kata Containers

Kata Containers is a credible stronger-isolation candidate because each workload can execute behind a lightweight virtual-machine boundary. It is **not selected for the 3.0 alpha**. Selecting Kata would add materially different prerequisites and trust surfaces:

- KVM or another supported hypervisor, including nested-virtualization availability in test infrastructure;
- pinned guest kernel, initrd/rootfs or image, hypervisor, runtime shim, and configuration provenance;
- device-model, shared-filesystem, networking, secrets-injection, and host/guest attestation boundaries;
- VM lifecycle, crash recovery, cancellation, residual-disk, and stale-hypervisor cleanup behavior;
- a dedicated threat model and a real adversarial corpus on representative deployment hosts.

Hosted CI used by the current reference gate does not establish those guarantees. Kata remains a non-blocking alternate, not an implicit fallback. Re-open selection only after the prerequisites above have pinned provenance, an approved threat model, and reproducible cleanup and isolation evidence. A future Kata adapter must not inherit gVisor assurance merely because both can be reached through OCI or Kubernetes `RuntimeClass`.

## Re-evaluation triggers

Re-run selection if the pinned gVisor release changes, `systrap` support or threat assumptions materially change, the reference deployment environment requires VM isolation, or Kata obtains the required provenance and representative-host evidence. Any re-selection is a new gate decision; it is not a configuration-only change.
