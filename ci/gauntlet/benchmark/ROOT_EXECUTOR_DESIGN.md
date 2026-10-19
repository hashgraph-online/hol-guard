# Root-created executor: design and prerequisite controls v1

Status: incomplete design/prototype, not a supported protected lane. Existing
Podman profiles, masks, seccomp/LSM policy and task permissions remain unchanged.
No product/task execution or efficacy claim is authorized by this document.

## Measured constraint

The retained control 003 measured `mount_too_revealing=1` on the exact failing
Bubblewrap proc mount after its security hook returned zero. This is the
kernel's mount-visibility rejection, not a generic inability to create user
namespaces. Linux 6.8 evaluates this check for mount namespaces owned outside the
initial user namespace. Existing overmounts cannot simply be bypassed by making
another unprivileged user namespace.

References: [Linux 6.8 mount checks](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/namespace.c),
[Bubblewrap 0.11 setup/privilege code](https://raw.githubusercontent.com/containers/bubblewrap/v0.11.0/bubblewrap.c).
These explain the mechanism; the retained syscall/BPF control is the actual local
measurement. The proposed Root-created setup has not established conformance.

## Designs to distinguish

1. A different outer Root-created namespace alone may still inherit the same
   nested proc visibility restriction when all masks remain. It must be measured;
   a Root-created process is not automatically a functioning native executor.
2. A separately versioned delegated namespace constructor could perform privileged
   mount construction before dropping all identity/capability authority. This is
   a new backend, not a fabricated Podman record or an availability override.
   The installed Guard would still have to own normal receipt validation, double
   authorization, overlay checks/admission, exact output binding and mandatory
   Post. No Root service may expose arbitrary commands, filesystem roots, FDs or
   caller-selected namespace handles. Integration and its attack surface remain
   unimplemented/unreviewed.
3. Removing masks, exposing a host proc bind, adding product/task capabilities,
   weakening syscall/LSM controls or substituting a mere VM backstop is excluded.
   Alternative protections cannot be silently treated as an approved exception.

The immediate bounded control evaluates a trusted initializer with the existing
mask set preserved. It can establish privilege-drop/gating facts and test whether
Root initialization alone resolves the unchanged probe. It cannot activate any
protected workflow cell or establish backend equivalence.

## Initializer contract

`root_executor_initializer.c` is a trusted, non-setuid, non-file-capability helper.
Only an already privileged outside controller may place it inside a newly created
private PID namespace. It requires Root real/effective IDs and PID1 before setup;
it adds no capabilities. It closes all inherited FDs except stdio, clears its
environment, sets private umask and bounded rlimits, clears ambient/keepcaps,
locks Root-exec capability fixup, empties the bounding set, drops supplementary
groups and real/effective/saved UID/GID to 10004, clears all capability sets, and
sets no-new-privileges and nondumpability. Failure exits before candidate imports.

Its ready marker is not an attestation. The outside controller must measure the
blocked process's actual identities, all capability sets, NNP, groups, FDs and
namespace separation through kernel interfaces. Only then may it release the
one-byte gate. EOF or a wrong gate byte must refuse execution. The gate descriptor
is replaced by `/dev/null` before exec. No Root initializer remains inside that
PID namespace once actor code begins.

These rlimits do not replace cgroup memory/CPU/PID limits, a hard wall deadline,
seccomp, LSM, read-only inputs, minimal devices, exact task UID idmapping or owned
descendant/mount cleanup. The prototype control runs trusted capability code
only, not Guard/candidate/task code, until all those controls are actually proved.

## Required review and acceptance evidence

Before any new profile is used for protected claims, pin its source/helper/binary,
compiler/runtime, image, kernel, mount plan, syscall/LSM policy and controller
protocol. Preserve the original physical UID10001 task custody and observed
UID10004 product view without chowning or widening access. Require fresh private
PID/mount/net/IPC/UTS boundaries, fresh proc and the declared masks, zero actor
capabilities, NNP, no inherited controller authority, read-only public inputs,
minimal devices, cgroup resource ceilings and terminal owned cleanup.

Independently measure forbidden controller/agent/peer paths, FDs and network;
input/output binding, one-use/replay refusal, cancellation, hard timeout and
descendant cleanup. Then exercise the actual installed native availability probe,
actual SDK Pre → contained sink → Post, and useful task continuation. An isolated
capability result cannot substitute for these end-to-end requirements.

Only after matching-source evidence and written equivalence review may a new
backend be advertised. Independent user review and existing verifier eligibility
governance remain distinct; author-controlled evidence does not supply either.

## Actual prerequisite result, 2026-10-14

Control 003 compiled the pinned initializer and externally observed every blocked
actor at real/effective/saved/filesystem UID/GID10004, no supplementary groups,
zero effective/permitted/inheritable/bounding/ambient capabilities, NNP and only
stdio descriptors. It verified distinct PID/mount/net/IPC/UTS namespaces, readonly
root, the declared proc masks, and cgroup 1 GiB/128 PID/one-CPU limits. Allowed
execution created a UID10004/mode0600 marker; EOF/wrong gates and cancellation
created none. The actual service deadline stopped the blocked actor after 22.54 s
including stop grace. All eight owned units across the three retained attempts,
their cgroups, scoped LSM profiles and image mounts were absent at export.

The nested probe still failed mounting proc, with no overlay effect. Its JUnit
retains that failure alongside six passing initializer controls; it is not a
passing native conformance result. No Guard/candidate/model code ran. This trusted
prototype does not establish syscall-filter or task-idmap equivalence and must
not be used as an untrusted product lane. Failures 001/002 remain separate: startup
before the gate and invalid integer FD keys in the strict JSON export.

A different trusted normal-host comparison then succeeded with the same pinned
Bubblewrap binary and zero-capability UID10004 actor. Outside inspection confirmed
the new file, char-device whiteout and opaque directory. No existing proc masks
were changed. This favors the normal environment inside a dedicated product VM
described in [PRODUCT_VM_DESIGN.md](PRODUCT_VM_DESIGN.md), keeping Guard's native
backend unchanged. The new VM is OS-provisioned only; its equivalence, transport,
actual installed Guard/SDK execution and lifecycle proof remain open.
