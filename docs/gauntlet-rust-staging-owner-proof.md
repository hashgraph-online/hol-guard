# Rust-owned candidate staging control: implementation proof

This slice gives Rust ownership of one diagnostic candidate control while
preserving the existing passive release observer and the Python controller's
locks. It does not create a conformance package, mark a candidate ready, or
enable a PR gate. The terminal outcome is always `invalid-evidence` until an
independent signed-record and physical-effect scorer exists.

The Linux ARM `gauntlet-candidate-staging-control` accepts only fixed build,
run, source, version, config, private-cell, prefix, controller, interpreter,
worker-binary and role pins. It verifies its installed Root-owned executable,
the positive source-matched conformance readiness, the held interpreter inode
and SHA-256, and the complete controller tree. A distinct Root-owned staging
journal reserves the run under an exclusive lease. Rust generates a sealed
Ed25519 controller key, durably records the started marker and key pin, emits
the prepared frame, and waits for the Mac host's durable key pin and
acknowledgement before launching the adapter. Rust then owns the controller
cgroup, 30-minute boottime deadline, cancellation, process observation,
descendant reaping, cgroup drain and product-slice stop. It retains a one-use
Root-only adapter log and a canonical diagnostic terminal; it does not trust
the adapter's cleanup claim as a benchmark verdict.

The macOS `gauntlet-host-staging-control` constructs exactly one canonical run
frame and one fixed Lima/sudo guest command. Its private host journal fsyncs
the guest's public-key pin before sending the acknowledgement. A failed or
uncertain handoff is reported as unresolved, with no replay or automatic
promotion. The bounded wait reports only an ineligible host diagnostic;
terminal and signed record readback remain separate work.

The source-matched Python controller was prepared without changing the active
Python installation. A read-only Git verifier matched all 427 `ci/gauntlet`
source blobs at commit `f58c03aaf903755e42eb48c68d9c820bf6e9e962`,
3,928,143 total source bytes, against the exact integration map. The map's
SHA-256 was `9ce59964afb73a3cb9b4809a74b614ddc9aeb5a846bab8a7633dc64c1c484574`.
The independent install plan selected 396 files and 407 non-root entries,
giving tree SHA-256
`be835c70dd4435463568c7417e7330de21cc251618c0473b785ffc218f03e910`.
The Root installer accepted the exact Git archive and map in the idle ARM VM
and installed `/opt/hol-gauntlet/controller-f58c03aaf903755e`. It reported
`controller_executed:false` and `execution_eligible:false`.

Local checks: the 427-file source inventory, the current install-plan tests,
Rustfmt, native host Clippy and warnings-denied Linux ARM worker Clippy pass.
The previous PR head's two isolated CI jobs failed because the install-plan
test still expected 426/395 files; this slice updates that expectation to
427/396 and the independently derived new tree digest. The final PR-head CI
result remains open.

The first actual host handoff used run `0c83a264b4569830` with a
SHA-matched Root-owned ARM executable `685202e4…`. The host durably pinned its
public key, but the guest refused before spawn: the staging plan had added
`PYTHONDONTWRITEBYTECODE` outside the descriptor launcher's fixed environment
allowlist. The host and guest both exited 2. Readback found the 0600 host pin,
Root-owned started marker, key pin and empty log; `/home/hx-0c83a264b4569830`
and its controller cgroup did not exist. No terminal or control record was
claimed, and the consumed run ID will not be replayed. The extra variable was
removed; the fixed `python -B` launch still suppresses bytecode in the
controller process. A new Linux ARM unit test joins the staging plan to the
descriptor launcher's actual fixed environment. Its SHA-matched VM test
binary `795881780e05363c58e249a7dbfd7949c1948741b3c2f5c370b7e646907ac357`
passed all 74 runnable worker library tests (three fixture tests intentionally
ignored). Warnings-denied ARM Clippy also passed. The corrected static guest
binary has SHA-256 `fb57aaed8077980094bc220a0af72bfc1a16376db84d2f3659c1dc0cb7a51ab5`
and was installed separately at its hash-derived Root path for a fresh run.

The controller install and executable compilation are infrastructure evidence
only. No fresh control, signed record, model request, full six-role package,
independent physical-effect verdict, host/VM crash handoff, or production
cutover is established by this proof.
