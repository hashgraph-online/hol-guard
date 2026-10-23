# Gauntlet Rust migration

This independent Cargo workspace is an implementation slice of the
[Gauntlet Rust migration plan](../../docs/gauntlet-rust-migration.md). It builds
Gauntlet's trusted code separately from the HOL Guard product workspace in
`rust/`; a candidate product build must never supply its own verifier.

`gauntlet-contracts` accepts bounded JSON byte records, rejects
duplicate keys and nonfinite values, reproduces the Python canonical JSON
bytes and SHA-256 digest, and applies the Python depth, node, byte and decimal
integer limits. It recognizes Python's UTF-8/16/32 byte-input encodings. The
golden cases and 256 deterministic float vectors were produced by
`ci/gauntlet/benchmark/json_data.py` at
[`b4efd817`](https://github.com/HGraphPunks/hol-guard/blob/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/ci/gauntlet/benchmark/json_data.py)
in [Gauntlet PR #5263](https://github.com/hashgraph-online/hol-guard/pull/5263),
whose file SHA-256 is recorded in the tests. That benchmark implementation is
not yet on `main`. It also checks the 22 copied Draft 2020-12 schemas,
Python's strict integer typing, all seven runner declaration versions, exact
external config digests, asset-role declarations, and candidate/test-merge
source identity claims. It also binds frozen campaign and gate-policy bytes
to all seven declarations, checks selected-cell policy/reservations/shards,
and hashes ordinary asset files through bounded no-symlink descriptors.
The composite v1–v7 inert config loader also reproduces Python's runtime/path
declarations, rejects symlinked private-cell paths, and checks v5–v7 installed
version metadata against outside source/native/version pins. It does not
authenticate the full installed prefix or admit a candidate to execution.
An inert SDK and installed-prefix inventory hashes metadata and bytes through
descriptor-relative directory enumeration. Linux `openat2` confines symlink
resolution, and a retained VM deployment gave positive Python/Rust parity for
all 13 asset roles. A Linux unit test rejects a file changed after hashing
starts; directory and symlink swap races still need proof. No Rust input check
authorizes execution.
An optional full inert inventory also checks all declared file and tree roles
and the Root-owned private-cell artifact set. Its private-cell manifest must
match 36 bootstrap files embedded from this controller generation, the exact
fixed file set, and the outside initializer pin; the embedded source-map digest
matches the current Python producer. The retained v7 VM deployment passed the
positive inventory comparison, 13 altered asset-digest refusals, and 13 more
path/kind/version/source/symlink/mode/byte refusal cases with mapped Python
and Rust stages; see the [Linux proof](../../docs/gauntlet-rust-linux-asset-proof.md).
Complete reason-class parity and older-version assets remain open before
execution admission.

A read-only v1 provider-quota reader checks outside config/allowance pins,
private file custody, the Python writer lock, canonical hash-chain rows and
reserve/settle/uncertain/extension accounting. It matches six Python-frozen
snapshots and rejects nine malformed or unauthorized journal variants; the
synthetic [quota proof](../../docs/gauntlet-rust-quota-proof.md) includes Linux
ARM64 test evidence. It cannot append a journal row or admit model inference.
An additional read-only helper checks historical provider observations against
ordered prefixes of that journal and an outside final-hash pin; it has only
synthetic fixture evidence and no live provider authority.

Pure [provider-status and controller-invocation reducers](../../docs/gauntlet-rust-controller-invocation-proof.md)
match 18 and 14 additional Python-frozen cases over operational accounting.
An idle-only, no-symlink private-file reader can supply those bytes to the
reducer. Live Root-owned VM proof, shard-ledger binding and provider-snapshot
authentication remain open.

`gauntlet-host-shadow-idle` is an uninstalled, summary-only diagnostic for the
existing Python host state. It attempts a nonblocking shared lock on the
private `agent.lock`, reads bounded job records only if the Python observer is
idle, and rechecks directory and lock identities before returning. While the
retained observer was active, the live diagnostic exited 2 with `Python
observer owns the host state`. It does not take over the observer, reconcile
VM receipts or publish a snapshot; see the [idle-lock proof](../../docs/gauntlet-rust-host-idle-lock-proof.md).
The separate `gauntlet-host-shadow-reconcile` diagnostic uses Python's fixed
read-only VM `reconcile` request for one retained historical job. Rust compares
the returned source, job and deployment identities to the host record and
matches Python's terminal-state mapping without saving the job or posting a
status. One retained pass agreed across host and VM; a build-failed job had no
VM terminal receipt and remained unknown to reconciliation. The response is
still producer data, not an independently authenticated verdict; see the
[reconcile proof](../../docs/gauntlet-rust-host-reconcile-proof.md).

`gauntlet-evidence` reads a workflow public bundle through no-symlink,
descriptor-relative paths. It checks externally pinned manifest and source
identities, Ed25519 signatures, file inventory and hashes, signed World
receipt chains, campaign inventory, and scheduled episode bindings. The
pure episode reducer matches 17 Python gate cases when supplied already
audited scores, native surfaces and cleanup observations. A pure campaign
reducer matches 16 Python ledger/accounting cases. Neither function
authenticates those observations or grants a production campaign verdict. A
pure [deterministic injection-attribution reducer](../../docs/gauntlet-rust-injection-attribution-proof.md)
matches 12 Python-frozen forwarding/withholding cases with authentication
deliberately stubbed in the fixture producer. It does not verify signatures,
SDK/kernel custody or a full control verdict.
The [controller signed-envelope verifier](../../docs/gauntlet-rust-controller-envelope-proof.md)
matches a Python `cryptography` Ed25519 fixture and rejects altered or ambiguous
records using an outside public key. It has no live controller-record custody or
independent evidence for the effects asserted inside a signed record.
The [signed injection composition](../../docs/gauntlet-rust-signed-injection-composition-proof.md)
binds the synthetic `extra_probes` signature and declared key to the outside
key before pure attribution. It still cannot authenticate the outer SDK result
or award a deterministic control pass.
The [deterministic control opening](../../docs/gauntlet-rust-control-opening-proof.md)
matches 23 Python-frozen signed/runtime/backend cases, including nested
Ed25519 records and outside conformance pins. Session, SDK, Native, kernel and
product-effect checks still must be ported before a complete control verdict.
The bounded HMAC VM bridge codec
matches Python frame bytes and poisons replayed,
tampered or misdirected connections; it has no live transport or key delivery.
The `gauntlet-verify` binary reports integrity and completeness only. Every
successful report remains `exploratory` and `qualification_eligible: false`;
it does not independently score Guard behavior or publish a CI status.
Python-exported valid and signed hostile fixtures provide differential tests.
The [parity manifest](parity-manifest.v1.json) records SHA-256 hashes for all
420 pinned Gauntlet source files and a preliminary owner phase.
The separate [integration source delta](integration-source-delta.v1.json) records the
48 files changed and seven files added when that pinned source is combined with
current `main` in draft PR #5402. A Rust test reconstructs and hashes all 427
tracked `ci/gauntlet` files; the original 420-file manifest remains the
immutable #5263 fixture baseline. Neither manifest makes candidate code a
trusted controller generation.
`gauntlet-contracts` also parses fixed, versioned [VM worker requests and responses](../../docs/gauntlet-rust-worker-protocol.md)
with no command or path selectors and explicit unknown/unavailable states; no worker dispatcher or receipt authenticator exists yet.
`gauntlet-evidence` checks the pinned Python worker's terminal receipt against caller-supplied source, job, deployment and config pins and the exact report bytes. The pure consistency helper does not open VM paths or award benchmark eligibility.
An uninstalled [Root-only Python-worker shadow](../../docs/gauntlet-rust-python-worker-file-proof.md)
now reads one retained receipt and report through fixed no-symlink private
paths before applying that verifier. A SHA-matched ARM64 binary accepted one
retained VM pair as internally consistent, refused unprivileged access and a
wrong config pin, and still reported `execution_eligible: false`. Its pins
were observed on that same VM, so this is diagnostic custody proof rather than
an independently authenticated control verdict.

`gauntlet-provider-observer` is a separate read-only socket client for the two
fixed local-model GET endpoints. It resolves only the pinned local route to
`192.168.5.2` on port 8001 or 8002, refuses redirects and oversized or
ambiguous HTTP responses, and applies the Rust one-model and provider-status
checks against outside pins. Its local tests cover response framing and a
Python-frozen idle provider snapshot. The uninstalled `gauntlet-provider-shadow`
binary accepts one bounded v1 JSON request on stdin and reports an unavailable
route with a nonzero exit; a SHA-matched ARM64 build did so in the idle VM
while the host model provider was offline. It has no inference POST, quota writer,
trusted provider generation or benchmark eligibility. See the
[provider observer proof](../../docs/gauntlet-rust-provider-observer-proof.md).

`gauntlet-dashboard` is a read-only shadow server for the existing public status directory. It embeds the current dashboard HTML, JavaScript and CSS, reads only bounded regular files through no-symlink descriptors, and serves the same `/api/status` and `/healthz` values on loopback. It does not own the observer, VM, queue or port 8791. To compare it with the Python dashboard, run it on port 8792 with the absolute **public** directory (never the private state root):

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-dashboard -- --state /absolute/path/to/.gauntlet-ops/public --port 8792
```

On 2026-10-20, a side-by-side read of the live public directory produced equal status JSON after excluding the time-sampled `collector_age_seconds`; the health values were equal and the three static assets were byte-identical. The Rust server does not change the authoritative Python controller or its port.

To verify the standalone shadow's port, run `ci/gauntlet-rs/target/debug/gauntlet-dashboard --healthcheck --port 8792` after building it. The check requires Gauntlet's JSON service name and a valid or explicitly absent instance ID, so an unrelated local HTTP 200 cannot appear healthy. An absent ID leaves collector readiness to `/api/status` without marking the server process unhealthy. In the container, `--healthcheck` keeps the internal port 8787 default.

The Rust dashboard also has an isolated Compose shadow. Supply the absolute **public** status directory, then build and launch it with one command. This Mac uses the `colima` Docker context and port 8793 because the local process shadow already uses 8792:

```sh
GAUNTLET_PUBLIC_STATE=/absolute/path/to/.gauntlet-ops/public docker --context colima compose -f ci/gauntlet-rs/dashboard.compose.yml up -d --build
```

Compose binds only host `127.0.0.1:8793`; the container reads `/state` without write access, runs as UID/GID 65532, drops all capabilities, and has a 0.25-CPU/128-MiB limit. Its built-in health probe checks the dashboard process, while `/api/status` continues to show the observer's actual stale or unavailable state. Use `GAUNTLET_RUST_PORT` only if another local port is needed. This command does not start a Rust observer, VM job or PR gate. The [container proof](../../docs/gauntlet-rust-dashboard-container-proof.md) records the live comparison.

`gauntlet-worker-state` is an inert durable journal library for the future Linux worker. It consumes a fixed `run` request only after independently supplied source, deployment and worker-generation pins match, creates one-time canonical started and running markers with exclusive no-symlink file creation, and fsyncs the files and directory. It can also persist bounded canonical report bytes and a versioned terminal receipt bound to the started marker and process identity. Restart reads detect orphan, partial, symlinked or changed evidence and block replay. It does not launch a process or authorize benchmark execution.
Its read-only response projection emits the fixed v1 protocol: an untouched job is `not-started` for progress, a started job is `running` only when a fresh Linux pidfd/start-tick/cgroup sample matches its durable marker, and a changed report cannot become terminal success. `inspect` and unstarted `run` remain unavailable until the Linux worker has complete trusted deployment and dispatch code.
An inert [fixed launch plan](../../docs/gauntlet-rust-worker-launch-proof.md)
reproduces the pinned Python worker's deterministic `ci check` argv, cwd,
environment and output paths for two Python-frozen cases. It refuses wrong
deployment/interpreter pins and injected request selectors. It does not spawn
the controller or establish execution eligibility.
The separate `open_root_owned` entrypoint is reserved for a live Linux worker: it requires effective Root, no symlink path components, Root-owned non-writable ancestors and a final directory with no group/world permissions. Its nonblocking `active.lock` lease is descriptor-held through reservation and terminal writing, and fails if the visible lock file changes. Tests use the inert `open` entrypoint to prove lock contention without Root. Linux process/cgroup observations are implemented, but the live dispatcher and independently authenticated report are still absent.

`gauntlet-vm-worker-shadow` is an uninstalled Linux ARM64 read-only entrypoint. It accepts one bounded fixed request on stdin and three independently supplied source/deployment/generation hashes, reads only `/var/lib/hol-gauntlet-rust/worker-state`, and prints a v1 response. It refuses other platforms, CLI path/command selectors and untrusted state ancestry. `inspect` and an untouched `run` are unavailable; a reserved job is `running` only with a valid durable marker and fresh kernel sample. It cannot create a journal, reserve a job, launch a candidate or replace the current Python worker. The latest static 1.2 MB ARM64 shadow binary had SHA-256 `b498f6723a09c48daf3c2e0dc94bb3616dd6a74c3686499bb9298cd4959e932b` on both host and VM; an unprivileged request exited 2 with the expected Root-custody refusal. The separate Rust state directory there is empty and mode 0700.

The separate uninstalled `gauntlet-deployment-shadow` diagnostic reads the fixed `/opt/hol-gauntlet/candidates/<source>` declaration with a caller-supplied raw manifest digest. It checks Root-owned no-symlink ancestry and files, the exact manifest fields, canonical config digest, config source SHA and Root-owned controller/interpreter parent directories. It does not read controller source bytes, follow the interpreter, verify all assets or report a staged worker. A static ARM64 binary with SHA-256 `424c545eef4c5ac62807563bd68e6112f9185d0317b42c21b22db3dedd698d3f` matched on both host and VM; the read-only invocation matched the pinned v7 deployment and refused a wrong outside digest. Eleven worker-state unit tests passed unprivileged there. This does not qualify the draft artifacts for Root installation or candidate execution.
The [controller source audit](../../docs/gauntlet-rust-controller-source-audit.md) confirms why source verification remains separate: the retained installed Python controller is a curated generation that does not exactly match either tracked Git source map.
`gauntlet-evidence::plan_controller_install` derives the expected fresh Root-owned controller-tree digest from an outside source hash map using the pinned Python bootstrap's exact file selection and install modes. Its [Python-frozen current-branch plan](../../docs/gauntlet-rust-controller-install-plan-proof.md) covers 396 files and 407 total entries at digest `74c933269882a348524c74ebb7ed96a3ddaa9334a965632067585822c563afca`; it does not authenticate Git provenance or install a controller. The retained VM's staging tree predates the current provider handoff source and remains ineligible.
The uninstalled [Git controller source shadow](../../docs/gauntlet-rust-git-controller-source-proof.md) reads every `ci/gauntlet` blob from one exact local commit and matches all 427 source SHA-256 hashes against the embedded integration map before deriving that same install digest. It refuses a different source tree and never fetches, installs, runs, or grants execution eligibility. A trusted external source pin and Root-owned VM installation remain separate prerequisites.
An [isolated Linux ARM Rust installer](../../docs/gauntlet-rust-controller-install-shadow-proof.md) now reads every transferred source byte against a supplied map before creating a new Root-owned controller tree. It refuses an existing generation, a wrong tree pin and changed source, and verifies the complete tree before and after exclusive publication. A separate unprivileged VM diagnostic verified the retained new tree. No deployment points at it, and the unreviewed PR-supplied pins cannot authorize worker execution.
The separate uninstalled `gauntlet-prelaunch-shadow` composes the fixed deployment, whole controller tree, interpreter, v7 config, all 13 inert asset roles and fixed launch plan for a bounded `run` request. It retains the already-hashed interpreter descriptor through the other checks and plan construction. It only reads state and always reports `execution_eligible: false`; `gauntlet-controller-observe` reports a local tree digest without treating it as an outside pin. Both passed a [read-only retained-VM diagnostic](../../docs/gauntlet-rust-prelaunch-composition-proof.md). A separate [fixed interpreter probe](../../docs/gauntlet-rust-interpreter-exec-proof.md) used Linux `execveat` on the held executable and proved the venv prefix on the retained ARM VM. The measured controller/interpreter hashes are not reviewed install anchors, and Rust has not executed controller code or a benchmark job.

An uninstalled [fixed cgroup containment probe](../../docs/gauntlet-rust-cgroup-containment-proof.md) separately placed an inert shell and sleep grandchild in a new Root-owned, capped cgroup on the ARM VM before execution. It observed both tasks, killed the subtree, verified recursive drain and removed the group. It accepts no job or command selector and cannot grant benchmark eligibility. The actual worker launch, product cells, builder, deadline and terminal receipt are not yet composed with this mechanism.
The [contained interpreter probe](../../docs/gauntlet-rust-contained-interpreter-proof.md) now composes the held Python executable with that fixed cgroup for one inert launch. The ARM VM observed two tasks and the child at UID 65534 with no-new-privileges, then verified kill, drain and cleanup. Python `site` imports are disabled. This still has no controller execution, job marker, authenticated report or benchmark eligibility.
The [read-only product-cell sibling inventory](../../docs/gauntlet-rust-product-cell-siblings-proof.md) identifies a separate cleanup boundary: Python's `systemd-run` cells sit alongside that controller cgroup under `system.slice`. A Root-only ARM diagnostic observed zero retained cells on the idle VM, and the worker-state suite passed 21/21 tests. A future live Rust worker must bind and clean up every sibling product-cell unit before it can claim whole-job cleanup; the inventory alone is only a point-in-time refusal input.

Run the checks from the repository root:

```sh
cargo +1.88.0 fmt --manifest-path ci/gauntlet-rs/Cargo.toml --all --check
cargo +1.88.0 test --manifest-path ci/gauntlet-rs/Cargo.toml --locked
cargo +1.88.0 clippy --manifest-path ci/gauntlet-rs/Cargo.toml --all-targets --locked -- -D warnings
```

Run the read-only verifier with an absolute bundle directory and a separate
absolute JSON pin-file path:

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-verify -- \
  /absolute/path/to/public-bundle /absolute/path/to/trusted-external-pins.json
```

The pin file contains `controller_public_key` (base64 Ed25519 public key),
`manifest_sha256`, `source_identities`, and `effect_anchors`. The test fixtures
under `crates/gauntlet-evidence/tests/fixtures/` show the exact shape. Pins
must come from the trusted caller outside the candidate bundle.

Inspect pinned runner documents and ordinary file assets with a separate
trusted SHA-256 pin and a canonical absolute public asset root:

```sh
cargo +1.88.0 run --locked --manifest-path ci/gauntlet-rs/Cargo.toml --bin gauntlet-inputs-verify -- \
  /absolute/path/to/config.json EXTERNAL_CONFIG_SHA256 /absolute/path/to/assets
```

Add `--full-inert-assets` after the asset root to hash the declared SDK/cache
trees, installed prefix and private-cell artifact set as well. The JSON reports
the selected episode count, shard assignment, aggregate reservations and
installed version metadata when applicable. `execution_eligible` is always
`false`: even the full inert inventory does not prove OS execute access,
Linux symlink-race safety, independent verdicts or live candidate execution.

The next slices must finish Phase 0's behavioral matrix and Phase 1's full
asset/configuration custody, legacy evidence and independent scoring parity before moving
to the Linux VM worker and host observer. The existing Python Gauntlet, VM
jobs, model provider, dashboard and optional PR gate remain the authoritative
execution path until fresh source-bound parity and recovery checks justify a
controlled cutover. This workspace does not start a job or publish a status.
