# Dedicated normal-product VM: proposed execution profile

Status: OS provisioned and trusted isolation controls implemented; no supported
product adapter or equivalence claim. See [PRODUCT_VM_CONTROLS.md](PRODUCT_VM_CONTROLS.md)
for matching-source syscall, rootfs, task mapping and LSM evidence.
The subsequent [runtime transfer and installed identity diagnostic](RUNTIME_TRANSFER.md)
passed without executing product imports as Root. Actual SDK/contained execution
and protected workflow acceptance remain open.
The source/control results below choose the next implementation direction. They
do not enable protected cells or complete the active executor requirement.

## Why a normal product environment

The preserved-mask Root-initializer control reached UID10004 with all IDs/groups/
capabilities dropped, NNP, closed descriptors, private namespaces and bounded
cgroups. Its normal nested Bubblewrap probe still failed mounting proc. Merely
changing the outer initializer does not resolve that restriction.

A separate trusted capability control on the owned VM's normal host succeeded
with the same pinned Bubblewrap 0.11 binary and UID10004/zero-capability/NNP actor.
The full proc/overlay shell shape completed; outside inspection found the new
regular file, char-device 0 whiteout and directory with `user.overlay.opaque=y`.
It did not import Guard, run candidate code, or establish native/harness support.
No existing proc mask, global sysctl or product capability was changed.

Prefer a normal product environment inside its own disposable VM over introducing
a privileged execution backend into Guard. The installed product should retain
its normal authorization, receipt, overlay and Post implementation. The benchmark
must adapt its outer isolation and observation transport explicitly.

## Provisioned envelope

Owned VM: `hol-product-benchmark-20261014`, VZ/aarch64, 2 CPUs, 4 GiB RAM, 16 GiB disk.
It uses the same hash-pinned Ubuntu 24.04 cloud image as the existing owned VM,
SHA256 `7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc`.
There are no host directory mounts, SSH-agent/X11 forwarding, nested virtualization,
automatic non-SSH port forwarding, inherited proxy variables or package upgrades.
The VM contains no model weights, real accounts, customer data or benchmark oracle
answers. The original controller/agent VM and operator model remain separate.

The public Lima YAML is retained under
`../workflow-benchmark-local-assets/hol-product-benchmark-20261014.yaml` relative
to the repository root. VM creation is not executor acceptance.

## Required implementation and review

- Declare a new `linux-product-vm.v1` observation/transport profile. Pin VM config,
  base image, actual boot/kernel, readonly runtime/rootfs, product prefix/native/
  wheel/policy/compiler, Bubblewrap and Node. Do not emit synthetic Podman fields.
- Keep controller authority, scoring answers, model endpoint credentials/counter
  and agent runtime outside the product VM. Any bridge credentials must be newly
  generated benchmark-only authority, private to the controller and restricted to
  the exact owned guest/service. No credential discovery or host key-store access.
- Preserve UID10001 physical task custody and UID10004 product view through actual
  idmapped mounts. Copy only explicit public runtime and synthetic task/provider
  data into the guest; pin initial/final/synchronized states and every transition.
  Do not chown tasks, widen permissions or silently reconcile conflicting writes.
- Provide normal host-like proc availability within the private guest kernel.
  This is a separately scoped environment, not removal of masks from an existing
  container. Before product use, demonstrate equivalent controller/agent/peer,
  sensitive-interface and device isolation under the VM boundary. If equivalence
  cannot be established under the goal's floors, leave the profile unsupported.
- Retain zero actor capabilities, NNP, readonly inputs/rootfs, private runtime state,
  no product/agent egress, syscall/LSM protections and memory/CPU/PID/wall limits.
  No privilege or filtering exception may make the native probe succeed. Applying
  a weaker service profile and labeling it equivalent is not permitted.
- Cover hypervisor-facing channels explicitly, including AF_VSOCK. A private
  network namespace alone does not establish denial of every socket/device family.
  Prove no access to host management endpoints or undeclared guest agent sockets;
  retain the syscall/LSM and device restrictions needed for that boundary.
- Authenticate the root bridge; its messages are inert bounded data selecting only
  explicit operations. Candidate imports never run as the collector. Observe
  actual native CLI PIDs/identities, arguments, data hashes, output, descendants and
  cleanup. The outside controller retains signing authority. Include both ends
  of the observation boundary, not product-supplied availability flags.
- Treat namespace identity as `(boot_id, namespace_id)` across different kernels.
  Numeric namespace/PID values can coincide across VMs. Version existing custody
  checks instead of pretending that a remote PID is a local Podman process.
- Bind every actual SDK Pre/contained/Post call and tool snapshot to one guest
  session and task revision. Synchronize contained effects before continuation and
  bind outputs exactly. Preserve normal native double authorization, receipt
  replay refusal, overlay admission and mandatory Post. Never substitute VM
  enforcement for a Guard intervention or task-utility measurement.
- Prove normal native availability and full actual SDK conformance, forbidden
  paths/peers/controller authority, network denial, cancellation, replay, real
  hard timeout and terminal owned process/cgroup/mount/VM cleanup. A capability
  control or successful VM boot alone does not qualify the profile.

After written equivalence review and matching-source conformance, integrate the
profile into the configured runner, freeze a fresh matrix tuple and execute real
paired workflows. Earlier refusals remain separate. Approval-service decisions
must remain distinct from unsupported Guard approval mediation; predeclared policy
must reflect the actual required surface without inventing product capability.
User independent review and trusted-base eligibility remain separate decisions.
