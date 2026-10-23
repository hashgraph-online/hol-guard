# Fresh candidate staging plan proof

The retained source-matched shadow candidate has a provisional v7 config, but
the installed `ci check deterministic` command needs an existing conformance
package. The first package therefore needs six fresh staging controls: five
conformance roles and an injection diagnostic. This change establishes a fixed
boundary for one control; it does not execute a control or admit a candidate.

`candidate_staging_plan.rs` accepts a 16-hex build ID, separate 16-hex one-use
run ID, exact source/version/config/private-cell pins, and fixed controller and
interpreter locations. Its role enum has exactly the six declared roles. It
derives the provisional config, `/home/hx-<run>` state, role record, cgroup,
product-cell slice, Root working directory, environment and `python -I -B`
argument vector. It accepts no arbitrary command or path selector.

`stage_control_adapter.py` is the one-role external executor. It requires an
isolated assertion-enabled Linux Root interpreter and consumes the existing
sealed Rust signing-key descriptor. It locks the installed Python worker and
CI check in their established order, verifies the pinned source-matched v7
config and all assets, creates or rechecks Root-only state, then invokes the
existing `run_control`. It reads the retained `control.json` through a
no-symlink descriptor with owner, link, mode, byte-limit and changed-file
checks. Its stdout contains only a record digest, public key, completion and
Python cleanup claims, with `execution_eligible: false`. Rust still needs to
read and score the signed record independently.

`staging_control_record.rs` adds that read-only Rust boundary. Given a caller
record digest and public key, it opens only `/home/hx-<run>/<role>/control.json`
through private no-symlink descriptors, compares two reads, loads the fixed
source-matched config, checks all inert assets and opens the signed control.
Its existing relation reducers cover reported output, route, prompt, Native
review and role-specific extra probes. It explicitly leaves physical effects
and process cleanup unauthenticated. The uninstalled
`gauntlet-staging-control-open-shadow` command exposes this diagnostic without
granting execution eligibility. A deliberately incomplete Python-frozen tail
fixture is refused by the complete opening, so a positive opening still needs
an actual retained staging record.

Validation on the integration worktree:

- Eight Python adapter/stage-outcome tests passed.
- Two Rust plan tests passed, including exact role/path derivation and refusal
  of malformed selectors and pins.
- The 427-file Gauntlet integration source inventory passed with the adapter
  explicitly mapped to phase 2 `port_to_rust` ownership.
- Warnings-denied `gauntlet-worker-state` Clippy passed.
- Thirty-one evidence library tests, the staging incomplete-record refusal
  test and warnings-denied evidence Clippy passed.

The next implementation step is a Rust staging supervisor that holds a
one-use lease, attests the controller and interpreter, pins a fresh signing
key to the host before spawn, owns the controller cgroup and product-cell
slice until cleanup, and reads each retained signed control. No live control
or model inference is claimed by this proof.
