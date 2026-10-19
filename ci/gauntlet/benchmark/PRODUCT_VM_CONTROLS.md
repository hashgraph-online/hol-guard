# Product VM isolation prerequisites

Status: trusted capability controls pass; the profile is **not a supported product
executor**. No Guard, candidate solution, SDK or model ran in these controls. This
does not complete executor equivalence, native conformance or workflow utility.

The owned product VM remains `hol-product-benchmark-20261014`, boot
`2598ce32-5155-4c33-affc-a014877cb931`, kernel `6.8.0-134-generic`, aarch64.
Controller/agent execution remains on the other owned VM. Production CI/CD and
existing masked containers remain unchanged.

## Implemented controls

`product_vm_seccomp.py` installs the actual zero-capability Podman OCI policy
captured from a trusted `sleep` container using the existing base image. The
container's kernel status confirmed Seccomp2. The captured policy has 21 rules,
default ENOSYS, native aarch64 plus ARM compatibility, and no capability grants.
Its exact JSON bytes are `product_vm_seccomp_oci_v1.json`, SHA256
`c904570e61ccaf7d03b9814796c625913650d08f97144e32e7030c19adbbfee5`.
The source containers policy SHA256 is
`cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c`.

The second filter restricts socket creation to Unix sockets and route netlink.
Bubblewrap requires route netlink to configure its own private loopback interface.
IP, AF_VSOCK, packet and other families are denied; non-route netlink is denied.
The second filter rejects compatibility ABIs, preventing socketcall bypasses.
This stronger restriction still needs evaluation against developer application
utility before the eventual executor profile is frozen. Private-loopback service
needs must be resolved explicitly without permitting external egress.

The loader requires all four UID/GID slots10004, no groups, all five capability
sets zero and NNP before loading the hash-pinned system libseccomp2.5.5. Either
filter failing raises an error; a trusted launcher must exit on that error.
The implementation follows the upstream [libseccomp API](https://github.com/seccomp/libseccomp/blob/v2.5.5/include/seccomp.h.in).
It never clears existing filters or interprets captured Python as configuration.

`product_vm_rootfs.py` runs only as Root PID1 in an already separate mount
namespace. It constructs a fresh mount tree, mounts normal private proc, binds
readonly OS/public inputs, exposes only six standard character devices, creates
bounded writable tmp/product mounts, pivots root, detaches the original root and
executes the existing hash-pinned C initializer. The initializer drops all IDs,
groups, capabilities and inherited descriptors before the trusted actor starts.
The actor installs seccomp before any product imports and blocks for outside
measurement. No candidate import runs as Root. This constructor currently has a
fixed trusted-control payload; it is not a general remote command executor.

An optional task bind uses the pinned util-linux2.39.3 mount/libmount binaries and
an actual `X-mount.idmap=b:10001:10004:1` mount. Outside observation verifies the
same device/inode/mode with physical UID/GID10001 and mapped UID/GID10004. A write
through that view produces a mode0600 physical UID/GID10001 file. Initial synthetic
fixture allocation establishes ownership; no existing task ownership or permission
is repaired to make access succeed. See upstream [idmapped mount documentation](https://github.com/util-linux/util-linux/blob/master/sys-utils/mount.8.adoc).

`product_vm.apparmor` is an enforcing inherited profile with no change_profile
grant. Its deny rules cover the sensitive files/directories masked in the existing
container. It uses path mediation in this newly constructed VM environment.
Existing masks are untouched. Outside Root observations confirm the exact enforcing
label. Direct/aliased sensitive-file reads, sensitive-directory listings and reads
inside a nested proc sandbox are denied. See the [AppArmor policy reference](https://www.apparmor.net/man/4.0/apparmor.d/).

## Retained evidence

Workspace-relative public export:
`../local-evidence-20261014/product-vm-controls-public-003/product-vm-controls-public-20261014-003`.
Its manifest pins 91 inert artifacts, SHA256
`16f55aa62dd2eecd0ec3797c3007c23c8d37f094cf66683c0d58f502478000b1`.
The inert audit is `product-vm-controls-audit-003/audit.json`, SHA256
`b84f99746b5050107a45a353f8fdf050940b80ccd6669c57ee2bad7ae4fe8d78`.
The audit verifies hashes, current source, actual kernel observations, task custody
and terminal state without importing captured code. This is author-prepared review
evidence, not independent review or trusted verifier eligibility.

The final `rootfs-009` control observes all six namespace identities outside the
actor, UID/GID/capability/NNP status, stdio-only descriptors, readonly root and
initializer rlimits. Actual cgroup files show memory1GiB, PIDs128, CPU1. It passes
socket denial, readonly write denial, sensitive-interface mediation, physical task
custody and the original nested proc/overlay operation. All 11 owned control units
are inactive, cgroups absent, own profiles removed and private rootfs mounts gone.
Owned VM disks and public evidence remain for continued implementation.

JUnit has 15 checks, **9 passes and 6 retained diagnostic failures**. They remain
visible: initial Unix-only filter blocked required route netlink; first rootfs
lacked `/dev/full`; task mapping failed before matching proc setup in two attempts;
one FIFO startup race; one directory-pattern omission. Each repair has a separate
control version. None is a model retry or a qualified campaign episode.

Focused matching-source regression: 136 passed, one Root-only skip; the exact Root
case separately passed. No added model usage: the shared counter remains18 used,
2,999,982 remaining, no pending or uncertain usage. Earlier reports retain their
original source bindings and are historical.

## Required next

Transfer only verified inert runtime inputs into a new readonly installed prefix,
implement the authenticated restricted bridge and versioned cross-VM custody, and
finish the written security-equivalence review. Prove actual installed native
availability, real SDK Pre → contained sink → Post, binding/replay/path/peer/network
negatives, cancellation, hard deadline and descendant cleanup. Then integrate the
new profile into preflight and freeze a fresh paired matrix before inference.
No supported/eligible flag is enabled by these controls. User independent review
of the eventual completed immutable package remains pending.
