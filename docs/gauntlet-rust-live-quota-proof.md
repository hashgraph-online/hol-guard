# Read-only Rust/Python parity on the retained model quota

On 2026-10-21, the uninstalled Mac Rust
`gauntlet-host-provider-quota-shadow` binary SHA-256
`cfd8e1e45eb2519dcb4abd59810cebea8825f4a5d07566ee6f83aad594794d7c`
read the existing owner-only Python v1 provider journal under
`/Users/construct/Documents/projects/hol-guard-refinement/goal-provider-quota-20261014`.
It used outside config pin
`ee39fb5f765aefab57005cc0db235faa076a22988d035cdb1a09a14fa33c86d1`
and allowance pin
`269508fcb01074d6bb07ef20505e90bc863fc85fca65a3a930ab93a8c23e2b28`.
The Rust reader takes a nonblocking shared lock and never appends to or resets
the journal. The pinned Python `ProviderQuota.snapshot()` read the same
journal, and parsed Rust and Python snapshots were exactly equal.

The matched journal hash was
`0452fa0f2e1eb555c6cf24d55334dd560b24a1b0ac772afe35f4068aed2c818f`.
It recorded 1,540 requests, 13,746,906 known and charged tokens, no pending
requests, no reserved tokens, `halted:false`, and a 14,468,885-token cap,
leaving 721,979 tokens. A wrong allowance digest and a wrong config digest
each refused with exit 2. Warnings-denied Mac host Clippy and Rustfmt passed.
The local Qwen model capsule remains mounted, but neither fixed host endpoint
on ports 8001/8002 was listening. No provider was started and no model tokens
were spent by this diagnostic.

The retained `beta-e2e` plan reserves 1,200,000 tokens before a full 12-cell
run, so the present settled allowance does not fit it. The existing allowance
record names candidate source `c1d18f931eaba02a37a2c9515db769fc2219bee8`,
whereas the current local patched shadow candidate is
`76c31929833b5571d25a56d9783e24a0997d5422`. The two-cell feature probe's
200,000-token reservation fits numerically, but it still requires fresh
source-bound conformance, provider generation custody and a Rust/Python quota
handoff before use. This snapshot is operational accounting, not an inference
or benchmark result.
