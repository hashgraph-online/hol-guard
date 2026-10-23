# Retained six-role Native MCP process attribution

On 2026-10-21, code commit `77e1ae0ccc1306e281166d42b30494f64d686fbe`
added an opt-in Rust verifier mode for the already retained six-role v5 staging
suite. It reuses the immutable host manifest SHA-256
`c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551`
for local build `b70d59e2681c4a3f` and source
`76c31929833b5571d25a56d9783e24a0997d5422`. No candidate, controller,
SDK, model or worker process was launched for this proof.

For each role, the verifier first repeats the v5 outside key, signed-control,
retained-file, terminal, SDK executable and cleanup checks. Its new mode then
verifies the nested Native MCP audit with that role's independently pinned
controller key. It finds one sampled non-agent Podman process with the audit's
boundary start tick, then requires both signed `proxy-process` PID/start-tick
pairs in that same sampled container and exact cgroup. The two proxy identities
must also share the boundary's boot ID, UID/GID, mount/network/PID namespaces
and no-new-privileges flag. Missing, duplicated, wrong-scope or changed tuples
refuse. The audit's boundary record has a start tick but no PID, so the
boundary PID is **inferred from one unique live sample**; the two proxy PIDs
are explicit in the signed audit.

| Role | Run ID | Sampled Native container | Signed proxy PIDs |
| --- | --- | --- | --- |
| success | `31e49073894ad659` | `d48369c6dc9e27bd0f13c791d912cd885012b8f37f30afd5a9b4920fd7c79b98` | 1318432, 1318446 |
| input-binding | `7dfe9e5ad361f6a7` | `bb1cb38d6079039fd8448bc2a0a5ca353b335b699774ff57e2106b62aa9bd84c` | 1319476, 1319490 |
| injection | `d822f45bd1d848f5` | `eb1abc552e5061eb14f7d884738233b3a3dc289106fc9bdc65c31f85d80b768c` | 1320700, 1320714 |
| boundary | `5fbfb7eb189d5436` | `9e8ae7dc51545b67a26579a403a23afe7ca635814051ae6521aedf89f5b5d9e4` | 1321868, 1321882 |
| timeout | `e4ddfa46c337f810` | `b834a84b46f78d12dfc2d02bb74f1921c45d4d6c3ff669dcc7386bd0fcd90807` | 1322899, 1322914 |
| cancel | `4f4af34f8fb5b34d` | `a8ee1ab4da4c7d8dae580a5cb35c7f53eb18e9b5b32f877867d438003290beb4` | 1323921, 1323936 |

The optimized static ARM64 verifier SHA-256 was
`eaae91118ae175c8013afe6c915ef0013e2ed12ad179bab1313b4016bf56e12a`.
The host and VM copies matched; the VM executable was Root owned, mode 0500,
one link. Its exact read-only invocation was:

```text
/opt/homebrew/bin/limactl shell hol-beta-bootstrap-20261016-004 -- sudo -n /root/gauntlet-staging-suite-shadow-eaae9111 b70d59e2681c4a3f c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551 --require-native-mcp
```

It exited zero with six signed records, six live Native MCP roles, 12 matched
proxy processes, six live SDK executable roles, 32 retained physical files,
five absent effects, six cleanup journals and absent post-run cgroups. Its
schema was `hol-gauntlet-staging-native-mcp-suite-shadow.v1`, with
`execution_eligible:false`. Changing one digit of the manifest digest refused
with exit 2. Supplying the older v4 manifest to the opt-in mode also refused
with exit 2. The same optimized binary, invoked without the new flag on the
same v5 manifest, exited zero and preserved the original
`hol-gauntlet-staging-suite-shadow.v5` output.

A SHA-matched static ARM64 evidence test binary
`6b25d62256c233e8c9900a94560b401ae4f756340286cc416216608e7dbc121f`
passed all 47 tests in the idle VM, including wrong PID/start/namespace/scope
cases. ARM64 warnings-denied Clippy, Rustfmt and `git diff --check` passed.
The first unoptimized verifier was stopped after it spent several minutes on
the full retained-file recheck; the optimized verifier completed the same
read-only proof in about 50 seconds. VM free disk after the copied diagnostics
was 9,082,830,848 bytes, above the 8-GiB floor.

The kernel tuples were sampled by the Rust worker during the earlier staging
runs; this verifier does not independently authenticate MCP frames, Native
contained-test effects, Guard policy decisions, or SDK tool-call causality.
The candidate source and controller generation remain local unreviewed
diagnostics. Every staging terminal is still `invalid-evidence`; no fresh
scored conformance package, model inference, production admission or PR gate
is established by this result.
