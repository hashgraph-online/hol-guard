# Inert product runtime transfer

`runtime_bundle.py` transfers an already installed public product prefix without
executing its interpreter, installation hooks, `.pth` files or modules as Root.
This is a bootstrap input format, not an executor, trusted verifier or deployment.
The original prefix and old artifacts remain unchanged.

## Fresh VM bootstrap (2026-10-15 local)

The second clean bootstrap installs the pinned Ubuntu 24.04 packages, kernel
`6.8.0-147-generic`, controller, repaired HOL Guard 3.46.0 runtime, SDK, Bun,
Node and three OCI images from 15 hash-verified public inputs (2,418,595,930 bytes).
The installer takes private Root-owned copies before consuming archives, checks
the controller file manifest, and installs public directories with explicit modes.
No manual PATH or umask repair was needed. Security sysctls remain unchanged,
host mounts are absent, and the VM ignores TCP/UDP forwarding except required SSH.

The first bootstrap's actual control 223 failed before SDK execution because
the base image retained util-linux 6.5 while the selected controller profile pins
6.6. The failed VM and evidence remain retained. OS bootstrap 003 now explicitly
installs `mount`, `libmount1` and `util-linux` version `2.39.3-9ubuntu6.6` and
verifies the existing profile's two binary hashes. The profile and its security
checks are unchanged. This repair was exercised from a new clean VM.

Fresh control 224 used immutable controller 058 and completed actual SDK MCP access and Native contained Node
execution, exactly one required Post, canonical output delivery, replay refusal,
same-UID peer refusal and kernel boundary negatives. Data-only verification
accepted the signed observations and rejected altered Post counts and fabricated
SDK output. An outside audit found no surviving owned actors, services, containers,
image mounts, profiles or cgroups. No inference ran in these controls, and no
product code was imported into the Root controller.

Local evidence is retained under `local-evidence-20261014` in the review workspace:

- `fresh-beta-control223-idmap-diagnosis-001.json` records the original failure.
- `fresh-beta-bootstrap-drivers-002.json` and `fresh-beta-public-inputs-002.json`
  pin the corrected setup drivers and all transferred inputs.
- `fresh-beta-control224-verification-001.json` records the installed execution
  and tamper checks; `fresh-beta-control224-outside-cleanup-002.json` records cleanup.

This is author-verified local setup and executor proof. Full normal CI runner
bootstrap-through-teardown, useful workflow validation and independent exact-byte
review remain open. The installed runtime is a locally repaired 3.46.0 candidate;
these results do not establish unchanged published-release compatibility.
The subsequent MCP discovery refinement changes an execution source and requires
fresh installed conformance before new workflow inference; control 224 remains
evidence for its exact preceding source.

## Contract

- `create_bundle(prefix, output, expected_tree_digest=...)` inventories the exact
  Root-owned tree and creates an exclusive deterministic `runtime-tree-bundle.v1`
  ZIP. Objects are stored without compression under their SHA256; timestamps and
  archive metadata are fixed. The manifest records file sizes, modes, ownership,
  kinds and links. The tree digest matches the existing product-prefix inventory.
- `validate_bundle(raw, expected_archive_digest=..., expected_tree_digest=...)`
  requires both external pins, strict bounded JSON, exact object membership and
  verified object bytes. It rejects duplicate records/members, path traversal,
  ambiguous paths, link ancestors, unsafe external/cyclic/dangling links, special
  objects, privileged modes, writable-by-others inputs and undeclared fields.
- `install_bundle(archive, destination, ...)` requires Root and exclusively
  Root-owned canonical destination ancestry. It validates before creating a fresh
  destination, installs files/directories before links, retains private root mode
  during installation and re-inventories before exposing the tree. It never uses
  `extractall`, creates hardlinks/devices or replaces an existing prefix. Partial
  failures retain an inaccessible destination rather than promoting it.

Budgets: 512MiB archive/tree, 128MiB per file, 100,000 entries and shared JSON
depth/node limits. Absolute interpreter links are limited to `/usr/bin/python3`
and `/usr/bin/python3.12`; all other links stay inside the prefix. The Linux/Python
base and native dependencies require their separate runtime pins. Byte transfer
does not establish executable ABI compatibility or permission to run as Root.

`product_vm_rootfs.py` optionally consumes an immutable Root-owned `runtime.json`:

```json
{
  "schema": "product-vm-runtime-mount.v1",
  "prefix": "/opt/pinned-public-runtime",
  "mountpoint": "/runtime/guard",
  "tree_digest": "<externally pinned tree SHA256>"
}
```

Only `/runtime/...`, `/home/...` and `/opt/...` mountpoints are accepted; the fixed
`/opt/node` dependency path, system, proc and controller/public paths cannot be
shadowed. Source ancestry and the complete
inert source inventory are checked before a readonly bind. An original installation
path can be preserved inside the new root for scripts with absolute interpreter
paths, without exposing the guest provisioning home. Runtime configuration is
trusted bootstrap input, never a product-controlled request to read arbitrary paths.

## Public SDK/cache transfer

`public_tree_transfer.py` provides a separate `public-tree-transfer.v1` format for
the existing public SDK profile: 2 GiB of file bytes, 100,000 entries, 16 MiB of
manifest JSON and a 64 MiB archive-metadata allowance. It does not change the
installed-product bundle limits. Both archive and tree hashes must come from the
trusted bootstrap configuration. The tree digest matches `freeze_public_tree`,
including UID, GID, mode and literal link targets. Only UID0/501 public inputs are
portable; actor-owned, world-writable, privileged, external-link and special-file
inputs fail validation.

Use `create_bundle(source, output, expected_tree_digest=...)`, then
`install_bundle(archive, new_destination, expected_archive_digest=...,
expected_tree_digest=...)`. Installation requires a fresh destination with Root
custody through every ancestor. It copies bytes before creating internal links,
preserves metadata, verifies each file and the final inventory, and never executes
SDK code or package hooks. Existing destinations are refused. Partial failures
remain private for diagnosis. OCI images require separate archive/image pins and
the normal Podman importer; mutable containers, credential stores and task state
are never dependency-cache inputs.

The current SDK export has 42,321 entries and 1,053,309,967 file bytes, tree
`4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1`.
Its archive SHA256 is
`4381adf1998b97031c4d6502e0b77b18d9f69f5cbcd0027b4ba584e5bed28691`.
Export and transfer roundtrip controls do not establish a completed clean-VM
bootstrap, workflow utility or independent verification eligibility.

## Historical runtime transfer proof

Transferred the repaired product into fresh owned VM prefix
`/opt/hol-product-runtime-20261014-001`. Actual source and destination both have
3,895 entries, 97,856,665 bytes, tree digest
`47627532bda91b6731b76c737365330efd8f66095883d18c341739855bf9fe38`.
The 99,336,167-byte archive SHA256 is
`0fbf96fa2aee6c4168b4cf478d5949d926c0b2ba1b2b66b9e79aa74f34815ca9`.
The transfer record SHA256 is
`b58ea0a6c5918246aadcd0eda2a8f82625fab2bf7e8b0306ad48bfc695b4aee5`.
Initial input lookup failed because the copy retained a nested directory; that
pre-installation failure is preserved separately. No prefix had been created.

The final VM diagnostic mounted the prefix readonly at its original installation
path. Only after the measured UID/capability/descriptor drop, enforcing LSM and two
active filters did the actor invoke its interpreter with bounded output/time.
The actual installed Guard diagnostic returned available/compatible/installed,
version3.43.1, source `89885ad54f13a1ccfa096d2ed17fdeb175fd7f06`, native SHA256
`a04aa4fdd858087cb45aa8be83a88f572e554b38b123f323c4160c8570adc274`.
Those returned identity fields remain product self-reports; Root separately binds
the prefix and invocation environment. This is not contained authorization, SDK
Pre/Post, task utility or qualification proof. No model calls occurred.

After invocation, outside Root inventory still matched the same tree. The owned
unit was inactive, cgroup/profile absent and private mounts gone. The 14-file public
export manifest SHA256 is
`310ece28a30d132715e157034266e8d3462c1e05ddd679c5b8eccfe9f2142806`.
Workspace evidence: `../local-evidence-20261014/product-runtime-diagnostic-public-001`
and `product-runtime-diagnostic-audit-001`. The inert audit has5passing checks,
SHA256 `a17a219ce9574f1e40fa280294534ec3a46822b8ef2c441b8a50a5dee540bcfe`.
It does not import captured product/solution code or establish independent review.

Focused matching-source regression:173passed,2Root-only skips; both exact cases
passed separately. Runtime transfer adds25hostile-archive cases and an actual Root
roundtrip, including deterministic output, inert hostile `.pth` data, retained
symlinks, existing-destination refusal and pre-write traversal rejection.

Next: authenticated restricted transport and versioned cross-VM custody; actual
native authorization and real SDK Pre → sink → Post with all required negatives,
deadlines and cleanup; then fresh frozen paired workflows. Production CI/CD,
existing masked environments, product authorization policy and trust governance
remain unchanged. The proposed executor remains unsupported until those proofs.
