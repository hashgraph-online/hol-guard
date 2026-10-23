# Bind retained SDK stdout to the control result

On 2026-10-21, code commit `d782f9954a3b2520cd492cc999f363eaea1c42cd`
strengthened Rust's descriptor-relative staging file audit. The audit already
required the Root-owned, single-link `sdk.stdout` bytes to match the retained
control's declared SHA-256. It now strictly parses those bounded bytes as JSON
(rejecting duplicate keys) and requires the parsed object to equal that
control's `sdk_result`. The single-role output schema is v2 and reports
`sdk_stdout_result_bound:true`. A unit test changes `sdk_result` while leaving
the stdout bytes and matching SHA unchanged; Rust refuses.

All six retained v5 roles had equal SDK stdout JSON and control results in a
separate read-only comparison. The new optimized static ARM64 suite verifier,
SHA-256 `c106eb1bd751bb94b701c44ec3152b38637049bc4234f12ef9e416336dcdf9b9`,
reopened the same host-pinned manifest
`c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551`.
It exited zero with six SDK executable and six Native MCP process roles, 32
retained physical files, five absent effects, six cleanup journals and
`execution_eligible:false`. Thus each of its six physical-file audits applied
the new stdout binding. The separate optimized physical-file verifier SHA-256
`4e4e475c0b4b9a64bc8fd8960b20faf5187732d5a6f47d6bd991df38c9abe461`
was installed Root owned, mode 0500, one link and returned v2 for the pinned
success role with five files, zero absent effects and
`sdk_stdout_result_bound:true`. Host and guest binary hashes matched before
execution.

The updated static ARM64 evidence test binary SHA-256
`0fa44e8e1c63d6db4b40bba82d4e44c1dbaf6b623c2f6eaad584da5fa2cbee32`
passed all 47 tests. ARM64 warnings-denied Clippy, Rustfmt and
`git diff --check` passed. VM free disk was 9,002,463,232 bytes after the
diagnostics, above the 8-GiB floor.

This binds the retained SDK capture file to the reported SDK result. The
file is still captured by the staging controller, not an independently
authenticated SDK transport tap. The check does not establish that the SDK
called Guard, that Native effects occurred, or that a Guard policy decision
was correct. The six terminals remain `invalid-evidence`; no source-bound
conformance package, installed control, model inference or PR gate follows
from this proof.
