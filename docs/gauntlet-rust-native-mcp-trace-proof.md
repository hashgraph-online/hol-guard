# Retained Native MCP transport and product custody trace

On 2026-10-21, Rust code commit `1f6903cf` extended the opt-in
`gauntlet-staging-suite-shadow --require-native-mcp` reader. It reopens the
same six Root-owned v5 staging records under host manifest SHA-256
`c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551`
for source `76c31929833b5571d25a56d9783e24a0997d5422`, build
`b70d59e2681c4a3f`, and prefix digest
`67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`.
It launched no candidate, controller, SDK, model, or worker process.

After checking each outside key and both controller signatures, Rust requires
the Native MCP audit and product-plane field sets, positive collection time,
inactive frontdoor, cleanup, unchanged prefix, private-cell MCP v2 profile,
source/prefix and package-version pins. The product claim's three version
fields are checked for consistency only; they do not authenticate the claim.
The signed boundary and proxy kernel identities must have UID/GID 10005,
empty effective and saved capability sets, matching saved UID/GID slots,
no-new-privileges, the controller's boot ID, and mount/network/PID namespaces
distinct from both signed controller and agent identities. Rust requires the
five declared mounts, including one self-bound read-only prefix and the four
fixed product destinations with their expected modes. It then repeats the
earlier unique boundary start-tick and two proxy PID/start-tick/cgroup matches
against the Rust worker's retained kernel samples.

The signed transport trace must be bounded, sequential, and from one run ID.
Every `child-started` row must uniquely match a signed proxy session, host
execution PID, product PID, full product identity, family, and UID-10005
backend. Every proxy must have a child row; authenticated UID-10001 peers
must number at least as many as those children; and the trace must contain a
forwarded `tools/call`. Unit cases reject a changed sequence or run ID,
peer UID, child identity, missing forwarded call, mount mode, capability set,
and wrong sampled PID or cgroup. The retained Python `verify_control` and
`evaluate_control` readers independently accepted all six records in the
[Python control parity proof](gauntlet-rust-retained-python-control-parity.md).

A cross-compiled static ARM64 evidence test binary with SHA-256
`a37885a093949e6f82d265ee0f3b132d8f46b10387be17955bb010e6dd9b7877`
was copied into the VM, checked against the host hash, installed as a
Root-owned mode-0500 single-link file, and passed all 47 tests. Warnings-denied
ARM64 Clippy, Rustfmt, and `git diff --check` passed. The optimized verifier
SHA-256 was
`6d92ead6da257d58a56a4902fdb160d694e29ade77ffbc0d8549fedd240f7f35`;
its host, VM inbox, and Root-installed copies matched. The read-only command
was:

```text
/opt/homebrew/bin/limactl shell hol-beta-bootstrap-20261016-004 -- sudo -n /root/gauntlet-staging-suite-shadow-6d92ead6 b70d59e2681c4a3f c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551 --require-native-mcp
```

It exited zero with six signed records, six matched Native MCP containers,
12 matched proxy processes, six SDK executable roles, 32 retained physical
files, five absent effects, six cleanup journals, and absent post-run
cgroups. The output remained
`hol-gauntlet-staging-native-mcp-suite-shadow.v1` with
`execution_eligible:false`. Free VM disk was 8,740,716,544 bytes after the
run, above the 8-GiB floor but with limited headroom.

Follow-up code commit `a75d6354` reused the existing Rust
`verify_product_kernel_identity` parity function for the boundary and proxy
checks, removing duplicate identity logic. A new static ARM64 evidence test
binary SHA-256
`8109d9bfcdaf2464123b29fedac742763794fcb0b0386aa61136b23abbd9aab2`
passed all 47 tests as a Root-owned mode-0500 single-link VM executable.
The optimized verifier SHA-256
`b64af16d95a128370300ad464dcef183cd356c46cb092ff4b5707ed152d66724`
was checked after transfer and Root install, then repeated the exact
six-role command above with `/root/gauntlet-staging-suite-shadow-b64af16d`.
It returned the same counts, schema and ineligible status. Warnings-denied
ARM64 Clippy, Rustfmt and `git diff --check` passed for the refactor.

Code commit `e6b7dc1f` added a bounded request/response reconciliation within
the same opt-in signed trace. For every `frame` row, Rust requires the next
`forwarded` or `delivered` row to have the same family, proxy session and
JSON-RPC message, in the declared direction. It tracks request IDs per
session, rejects duplicate or orphan IDs and unfinished requests, and
requires one completed `docs.read` call for `developer-spec` in each role.
Changing the paired request method or delivered ID refused in unit tests.
The new SHA-matched static ARM64 test binary
`c9879c2a9da2218c0563d6524000e0843ef671441626a11a2872abadf9a73707`
passed all 47 tests. The optimized Root-owned mode-0500 verifier SHA-256
`5b1dba940f75b94cb4659eb0eb2095b490331197b12c0b4eed793f413d6d3436`
reran the six-role command above with `/root/gauntlet-staging-suite-shadow-5b1dba94`
and returned the same ineligible schema and counts. ARM64 warnings-denied
Clippy, Rustfmt and `git diff --check` passed; VM free disk was
8,730,800,128 bytes after the run, above the 8-GiB floor.

These are signed controller observations cross-checked with earlier Rust
worker kernel samples. They do not independently capture MCP wire frames,
prove the SDK caused a tool call, authenticate Native contained-test effects,
or attribute a Guard policy decision. The image ID is matched between two
signed records, not to an independently reviewed host image pin. The
controller generation and candidate source still lack independent review.
All six terminals remain `invalid-evidence`; there is no fresh scored
conformance package, model inference, production admission, or PR gate.
