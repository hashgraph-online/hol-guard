# Passive SDK tap controller mount proof

Source commit `c60f4df1` adds an exact `--sdk-tap-v2` selector to the Rust
staging plan and Python control adapter. The ordinary v1 plan and adapter call
remain unchanged. The v2 adapter opens the one-use Rust tap directory through
no-follow descriptors under `/var/lib/hol-gauntlet-rust/staging-state`, holds
both directory descriptors for the controller lifetime, and compares the
visible Root-owned journal, group-10001 tap directory, and fixed docs/mail
socket inodes and modes before and after the run. The selected directory is
mounted read-only into the agent at `/runtime/resources`; the Native product
frontdoor and hook paths keep their existing sources. The adapter result
records `sdk_tap_v2_requested:true` and remains `execution_eligible:false`.

The explicit Rust v2 plan adds only the literal selector to the validated v1
launch vector. An ARM64 VM unit binary pinned by SHA-256
`c27c92de8f0e2d8f239b9f9ee662a526dae6336ba3659328c0f9bcfac3e4fde9`
passed the complete worker library suite: 92 passed, eight intentionally
ignored, zero failed. On macOS, the focused Python tests passed 18 tests and
29 metadata subtests; the broader deterministic/local executor selection
passed 162 tests before the final Root-directory identity recheck was added.
The final source inventory test and independent Python controller-tree digest
calculation agreed on 427 Gauntlet files (47 changed, seven added), 396
selected controller files, 11 directories, and tree digest
`eb1c9f9de6e936f072d368bfbc6fa8e8cf4f563407eecf19f7a10a866f1cfa44`.
The two targeted Rust inventory/installer tests, the full Rust workspace run
before that final Python recheck, Rustfmt and `git diff --check` passed.

This is a passive mount capability, not a live tap. The installed Rust staging
worker still calls the v1 plan and does not bind listeners or start the tap
child under its lease. No candidate ran with this controller source, no
installer/source generation has been independently reviewed or installed, and
the retained six controls are older, source-mismatched `invalid-evidence`
diagnostics. The tap child has no dedicated cgroup/namespace or host-pinned
terminal journal yet. No SDK wire, Native effect, Guard decision, model
inference or conformance eligibility is established by this proof.
