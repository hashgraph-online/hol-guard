# Six fresh Rust-owned staging controls

On 2026-10-21, the fixed Mac caller and installed Linux ARM64 Rust owner ran
the six diagnostic roles sequentially against the source-matched local
candidate. Each role used a distinct one-use run ID, a public key pinned on
the host before spawn, and a Root-owned signed record. The independent Rust
opener then read each fixed record from the guest and matched its raw SHA-256,
public key, source, revised v7 config, installed prefix, private-cell manifest,
and all 13 inert assets. The candidate source is
`76c31929833b5571d25a56d9783e24a0997d5422`; the revised config digest is
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`.

| Role | Run ID | Signed record SHA-256 | Host key-pin record SHA-256 |
| --- | --- | --- | --- |
| success | `24c449db48507c73` | `2a3dc8717455c55e45288a42530f516762d58a5128e802b951f5e45f1fabe2b8` | `b3e38b5f55be0bcb0ed6350ce14c1a29cb1ecafd14b55e84972ad678dd0597de` |
| input-binding | `4c707761bddc8a8f` | `6c982bd7bbaf3a931c552288c05c19c7a5255ad4c0cebd79ab282c0fe3dc4148` | `be463c753e427e27326d28d75339ef7bd9297fcca67ad0a95f3ed7f123ffe95c` |
| injection | `89ba9180548a2dd8` | `7a4126b4d720c2146ed9b96285c0daea1796dce51c6df237fb2a5e6f84c2f788` | `b9f4160b97798c6ca2ec004c536f4b16c3625b8dc440cd63c4230026ed4d98a3` |
| boundary | `5414af8615340866` | `ec3bc00e42c33ab8d8300adf78c9695ee5b715b41c9af11b3db8d9022ce3698b` | `9c1d10f09151768b11d5019c179293eeea2157313ff0a82a3a6bb87d512ef42c` |
| timeout | `7a8f24e4aa919ad0` | `d2f2a93ebb4263f2a122fd5caedb24d06c9b8360dcde522accd5b0a47205cb66` | `3fcd6a5753351e8af9a4526d4c4af3c7db650a1996d526614b37437a3ccd8ba5` |
| cancel | `f4b16eefe56009df` | `e35618941aebf84b03090504747839681e396fefe3db639d473a959314a2f4ad` | `07f263a2a840db48369934dd8f6dc562acf8e790e4a2f9d24a576cafd0a3c57c` |

Each host pin file was independently rehashed. Each opener returned
`outside_control_key_matched:true`, the expected signed session role, and
`execution_eligible:false`. Five roles had one recomputed contained route,
output binding, CLI result, and public prompt relation; cancel had the expected
partial relation with zero such completed results. Input-binding and injection
also passed their signed extra-probe checks. These are signed or
producer-reported relations, not independent evidence of physical effects.

The six Root-owned supervisor reports each say `exit_code:0`,
`timed_out:false`, `post_run_controller_custody:true`, and
`controller_and_product_slice_cleanup_verified:true`. Each retained terminal
has status `invalid-evidence`, by design. A separate Podman process listing
afterward was empty. The 48-GiB VM had 10,406,776,832 bytes free (79% used).
The reports say `record_scored:false` and `execution_eligible:false`; the Rust
opener says `independent_kernel_sdk_effects_verified:false`. No conformance
package, installed-control pass, model inference, or PR gate follows from this
diagnostic. The reused local executor image has not had an independent content
review. Fresh physical-effect scoring and a package constructed from these
separate signed records remain required.
