# Gauntlet Rust migration execution checklist

This checklist implements [the migration design](gauntlet-rust-migration.md). Check a box only after the stated exit evidence exists on a reviewed source pin. A local synthetic fixture establishes parser or verifier behavior, never a live Guard or model result. The pinned Python baseline is Gauntlet PR #5263 at `b4efd8171b06d0e13cbe12a077c376ecdc891fd1`; the Rust draft is [PR #5306](https://github.com/hashgraph-online/hol-guard/pull/5306). Preserve the release-only passive observer and optional PR gate until the rollout checks say otherwise.

## 0. Baseline, inventory, and differential corpus

- [x] Create a separate, locked Rust workspace outside the product runtime and an isolated read-only CI check. Evidence: `ci/gauntlet-rs/Cargo.toml`, `.github/workflows/gauntlet-rust-contracts.yml`, PR #5306 isolated `contracts` check at `8a7989c4`.
- [x] Record SHA-256 hashes and proposed owner phase for all 420 tracked `ci/gauntlet` files at the pinned Python commit. Evidence: `ci/gauntlet-rs/parity-manifest.v1.json` and `source_inventory_parity.rs`.
- [ ] Integrate the pinned Gauntlet control-plane source from draft PR #5263 into a reviewed base or an explicitly reviewed migration dependency. PR #5306 starts from `main` and currently lacks that Python control plane; no Rust worker cutover can rely on an unmerged candidate controller.
- [x] Enumerate the three Python CLI entrypoints, primary command/profile surfaces, operational job states, public snapshot boundary, file/tree asset roles and major journals with proposed Rust phase owners. Evidence: [command and state ownership matrix](gauntlet-rust-surface-matrix.md). Historical schemas, every status field, legacy exit codes and the 420-file dispositions still need the exhaustive audit below.
- [ ] Audit every manifest disposition and enumerate each CLI command, profile, schema/version, external executable, artifact role, public status field, exit code, journal and state transition with an owning Rust component.
- [x] Freeze Python-produced canonical JSON vectors, seven accepted runner declarations, and valid/incomplete, complete synthetic, and signed hostile public bundles. Evidence: Rust fixture tests under `ci/gauntlet-rs/crates/`.
- [ ] Add versioned golden cases and Python accept/refuse reason classes for the full config loader, source/archive/asset custody, HMAC/Ed25519 receipts, deterministic reports, provider quota, bridge frames, legacy evidence, dashboard snapshots, and interruption recovery.
- [ ] Resolve failures in the full repository CI run for PR #5306; identify branch-caused failures and obtain a green required aggregate before a merge proposal.

## 1. Pure contracts and trusted readers

- [x] Match Python bounded JSON parsing, canonical bytes, SHA-256, duplicate-key rejection, nonfinite rejection, depth/node/byte limits, and 256 float vectors. Evidence: `gauntlet-contracts` tests.
- [x] Pin and compile all 22 Draft 2020-12 schemas with strict Python integer typing. Evidence: copied schema hashes and `schema_parity.rs`.
- [x] Validate v1–v7 runner **declarations** and exact caller-supplied configuration digests, without executing or reading candidate assets. Evidence: `runner_config_parity.rs`.
- [x] Validate Python-frozen campaign and gate-policy document bytes, selected-cell policy bindings, serial reservation totals, shard layout, and protocol profile assignments for all seven runner versions. Evidence: `policy_parity.rs`, `runner_inputs_parity.rs`.
- [x] Read pinned campaign, policy and ordinary file assets through bounded descriptor-relative no-symlink paths, and require an execute mode bit for pinned Bun, Node, native and compiler files. Evidence: `gauntlet-inputs-verify` and `runner_inputs_parity.rs`; its output explicitly says `execution_eligible: false`. Full OS execute-access parity remains outside this check.
- [x] Add an inert SDK/installed-prefix inventory prototype with descriptor-relative enumeration, metadata, file byte hashes, symlink containment, ownership and mode checks. Evidence: `tree_inventory.rs` tests. Symlink race proof and installed-prefix positive parity still need Linux hardening and remain outside admission.
- [x] Match Python v5–v7 package-version syntax and read bounded installed runtime metadata through no-symlink descriptors, comparing source/native/version to outside pins. Evidence: `package_version_parity.rs`. Prefix custody and live installed identity remain separate checks.
- [x] Validate reported direct-candidate or two-parent test-merge source identity against independent pins. Evidence: `source_identity_parity.rs`.
- [ ] Implement full v1–v7 config loading: canonical root and no-symlink input reads, document byte pins, campaign/policy binding, selection/shard and reservation budgets, protocol mapping, and installed package version.
- [ ] Implement inert SHA-256 inventory of file, SDK tree, installed Guard prefix, private-cell artifacts, conformance package, compiler, Node, Bun, wheel, native binary and provider/model manifests; compare exact Python outcomes.
- [x] Verify workflow public-bundle custody using independent pins, Ed25519 signatures, World receipt chains, bounded no-symlink files, campaign and episode bindings. Evidence: `gauntlet-evidence` tests and exploratory `gauntlet-verify`.
- [x] Port the pure Python `_episode` gate reducer over already-audited inputs, including baseline measurement, approval, native surfaces, protocol exposure, inference, utility, security and cleanup dimensions. Evidence: 17 Python-frozen cases in `episode_score_parity.rs`; it cannot authenticate the inputs or grant eligibility.
- [x] Port the pure audited-campaign reducer for serial ledger accounting, retry violations, token/time caps, missing and duplicate terminal outcomes, and aggregate status. Evidence: 16 Python-frozen cases in `campaign_gate_parity.rs`; retained attempt authentication and live eligibility remain open.
- [x] Port the bounded HMAC VM bridge frame codec with Python byte vectors, sequence/direction/boot checks, aggregate limits and connection poisoning. Evidence: `bridge_frames_parity.rs` with a synthetic test key. Transport wiring and key delivery remain open.
- [x] Parse the pinned Python VM worker's terminal receipt and report as bounded JSON, comparing source/job/deployment/config, report bytes, zero-model deterministic profile and process exit against outside pins. Evidence: `worker_receipt_parity.rs` with a Python-shaped synthetic vector. Root-owned custody and independent control scoring remain open; this reader always reports `execution_eligible: false`.
- [ ] Recompute deterministic control verdicts and workflow task/security/exposure/intervention outcomes from authenticated observations; do not accept a producer-supplied `passed` flag.
- [ ] Verify HMAC and remaining signed custody formats, including quota and controller journals, with interruption and tamper cases.
- [ ] Port the legacy public-evidence reader and trusted-base eligibility rules for all retained evidence versions.
- [ ] Run Python and Rust readers over the same immutable golden set and reconcile every accept/refuse and reason-class difference.

## 2. Linux ARM VM worker and deterministic apparatus

- [x] Add a versioned, 1-KiB fixed-action request parser that rejects arbitrary command/path/profile fields and requires an external deployment digest for `run`. Evidence: `worker_request.rs`, `worker_request.rs` tests, and [worker protocol boundary](gauntlet-rust-worker-protocol.md). It does not dispatch or prove one-time execution.
- [x] Add a bounded response parser for fixed action/state pairs, external worker/deployment pins, started-marker and terminal-report digests, and explicit unknown/unavailable states. Evidence: `worker_response.rs` tests and [worker protocol boundary](gauntlet-rust-worker-protocol.md). It does not authenticate a receipt or prove execution.
- [ ] Define a fixed, versioned request/receipt protocol for `inspect`, `progress`, `reconcile` and one-time source/deployment-bound `run`; reject arbitrary command or path selection.
- [ ] Build a root-owned Linux ARM worker binary with durable job IDs, exclusive lease, restart reconciliation, monotone deadlines, PID/cgroup identity, and truthful unavailable telemetry.
- [ ] Port exact Git/archive provenance and the unprivileged, bounded Podman builder, retaining UID, AppArmor, seccomp, capability and `slirp4netns` controls.
- [ ] Port inert wheel staging, installed-prefix identity, fresh signed conformance, immutable deployment, and feature-audit invocation without importing a candidate as Root.
- [ ] Port product-cell isolation and six staging plus six installed deterministic controls; authenticate native Pre/Post and physical effects independently.
- [ ] Prove failure containment for moved tags, wrong archive/wheel/prefix, symlinks, replay, stale PID, timeout, cancellation, surviving descendants and uncertain cleanup.
- [ ] Run fresh exact-commit ARM VM conformance at 2 vCPU/16 GiB RAM/48 GiB disk with zero model requests and retained source-bound reports; keep the v3.48/v3.49 missing-capability finding visible.

## 3. Mac host, release observer, and dashboard

- [ ] Port `up`, `status`, `doctor`, `hold`, `resume`, `down`, `reconcile`, and `repair` with new versioned state storage and no concurrent ownership of Python locks/journals.
- [ ] Port release-only exact-tag discovery for v3.48/v3.49, optional isolated PR artifact handoff, queue admission, single observer lease, and unknown-job blocking.
- [ ] Port bounded Lima transport, source/build/stage/control progress, VM/headroom/progress sampling, and public snapshot publication with no private fields.
- [ ] Serve the existing loopback dashboard/API from Rust with correct instance identity, stale/unavailable states, active jobs and resource headroom.
- [ ] Shadow-read historical state, then test intentional interruption and read-only receipt reconciliation before a controlled observer cutover.
- [ ] Prove one-command deployment and port 8791 identity check without modifying current Python jobs or enabling a PR gate.

## 4. Model-backed workflow benchmark

- [ ] Freeze campaign, private cells and SDK/provider/asset identities; port serial shard/attempt scheduling and durable exclusive campaign journal.
- [ ] Define bounded authenticated Rust↔OMP/Bun bridge frames, event sequence, cancellation and terminal markers; keep the pinned TypeScript SDK as an external adapter.
- [ ] Retain the local mounted Qwen/MLX provider as a host-owned external process and port exact lifetime quota reserve/settle/halt semantics without resetting its journal.
- [ ] Port synthetic services and independent oracles for all declared clean, injected, protected, unprotected and approval cells.
- [ ] Port gate computation with separate execution validity, utility, security, exposure, intervention, attribution, provider accounting and cleanup dimensions.
- [ ] Run a fresh Rust-controlled two-cell MCP feature pair with actual inference, real tool calls and positive known provider usage.
- [ ] Run a fresh Rust-controlled 12-cell `beta-e2e` selection, then the wider 800/140/160-cell schedule; retain every attempt and treat missing/unknown evidence as red.
- [ ] Match current `ci check` status/exit semantics or introduce an explicit versioned successor; never promote unprotected attack measurements to Guard passes.

## 5. Legacy qualification, installed acceptance, and publication

- [ ] Port the pinned 128-scenario legacy catalog, fixture realism, subprocess workers, exact-call judge and signed evidence export/readers.
- [ ] Port OMP core qualification plus Watch/approval/native/full-task diagnostics while preserving each lane's existing claim limits.
- [ ] Port installed registration, repeat, aged-home and exact package/source/native identity checks.
- [ ] Keep trusted-default-branch verification separate from candidate execution and status writing; verify stale PR heads, forged producer metadata and candidate self-trust are refused.
- [ ] Verify old and new evidence against immutable Git blobs and historical trust exceptions; retain Python readers for unsupported old versions.

## 6. Rollout and retirement

- [ ] Build reviewed, immutable macOS host and Linux ARM worker artifacts from a trusted source generation, outside the candidate product workspace.
- [ ] Compare Rust/Python read-only verdicts, failure classifications, telemetry age, interruption/restart behavior and resource use on the same retained evidence.
- [ ] Exercise idle-only cutover and rollback with no active or unknown job, no duplicated provider use, no lost receipt and no replay.
- [ ] Publish a compatibility table for every config/evidence version and its trusted reader; remove Python orchestration only after all parity rows pass.
- [ ] Leave the PR gate passive until a separately verified live PR handoff and operator action explicitly enable the owned ruleset.
