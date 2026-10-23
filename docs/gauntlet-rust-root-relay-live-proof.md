# Live Root-forwarded PID-namespace SDK tap diagnostic

The opt-in `--root-relay` staging path uses the same fixed Python
`--sdk-tap-v2` mount as the previous tap diagnostic. A pinned PID-1 child,
running as UID/GID 10001, connects to the held Native frontdoor and passes
its connected descriptor to Root. Root owns and parses the SDK/Native byte
stream, checks the SDK PID/start/cgroup/ancestry and Native peer before each
write, and retains a distinct `hol-gauntlet-sdk-tap-journal.v2`. The staging
summary is v3, the journal receipt is v2, and every session declares
`wire_owner:root-forwarded`. The outside six-role reader has a separate
`--require-sdk-docs-oracle-root-relay` mode and refuses the old child-report
mode on these bytes. All outputs remain `invalid-evidence` and
`execution_eligible:false`.

The final Linux ARM64 worker-library test binary SHA-256 was
`f96aca1f91b28d4373c81ea6d2ce54fb6e01553946ec4a7af22ff1cd9233a816`.
On the dedicated 2-vCPU, 16-GiB VM, 101 default tests passed and 19
Root/fixture cases remained ignored by default. Separate Root tests passed
the simultaneous docs/mail Root-forwarded mode, its v2 journal, and the old
PID-1 child-forwarding regression. The source-mounted ARM64 evidence suite
passed all 52 tests. A standalone VM evidence binary passed 50 tests; two
source-fixture tests could not find their build-time `/src` path there, so
the same full suite was rerun in the source-mounted ARM64 container and
passed. The Mac host reader's Root/child ownership test passed.

The retained candidate was v3.49.0 source
`76c31929833b5571d25a56d9783e24a0997d5422`, build
`b70d59e2681c4a3f`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
private manifest
`66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5`,
prefix `67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`,
and separately installed draft controller source
`7364fbc27dc95d0de97c2d9ec157fbb54f832fdb` with tree digest
`01ba175093b9e9a7a114eedde2c213e9254426f079c8ec0c2b201b9ff2f0c4ec`.
The installed Root worker SHA-256 was
`f076e7135d698111ac438f2a735badd20b63d8bb69bdf6dd6d6f3d568985d0e5`,
the PID-1 connector ELF SHA-256 was
`a10d3027b99382e0f28871fcb593d1b95a4c1a0947b9128df22d00e5c86824c7`,
and the Root suite reader SHA-256 was
`313d5f0a59c83a03d4aff39333a2c9dd92b3268b964282bba26413e4448248b3`.
The worker was Root-owned, single-link, mode 0500; its first install at 0555
was rejected by its own prelaunch binary check before a key pin or guest
run. The corrected installation used a fresh run ID.

| Role | Fresh run ID | Host-pinned tap journal SHA-256 |
| --- | --- | --- |
| success | `d3fffa1ebca4dc00` | `5655d54d0b2174894aa1f4ae4d4222afee0ccf187e0863d50f4fb3d0e1282031` |
| input-binding | `781324b91b15b787` | `e3063194d0e8f0e05faea3051eca93cd4cf3621107825139c10484ee26af90fc` |
| injection | `2cbaf75234c24b2d` | `1647cc2f41f8668f946494038af90d725a552a55c676656b6aadf66daa56ff4e` |
| boundary | `db9a9f61aa817139` | `a0896591f9f3b04d6119beb3171ee617bd1d9bdecdb51473e556c5c70c83f513` |
| timeout | `3fed988d5db2f261` | `c5118f2e2a242c7e0bc231067d5a0578e7595274be169717e707a1b6e2f22a60` |
| cancel | `0665c67f782d08f5` | `e42185824452e94c4c8226dda5e78ef0c0ae1821630360ef0067218340f70f27` |

Each host prelaunch key pin preceded its worker acknowledgement; the host
then read and pinned 24 events in two Root-forwarded sessions after terminal
completion. The fresh v5 host suite manifest SHA-256 was
`e3db3bf75fa39355a5e769b5c4d31baa78d364e68aa6f968609dd348158d76c5`.
The Root reader matched all six role pins, 144 SDK/Native frames, six
source-bound docs records, twelve signed Native proxy processes, 32 physical
files, five absent effects, six cleanup journals, and absent outside cgroups.
Its output schema was
`hol-gauntlet-staging-sdk-docs-oracle-root-relay-suite-shadow.v1` with
`root_forwarded_sdk_tap_roles_matched:6`. Running the older
`--require-sdk-docs-oracle` reader over the same pins refused the success
role's v2 tap journal. The VM finished with 8,671,543,296 free bytes, only
81,608,704 bytes above its 8-GiB admission floor.

Review then found that the PID-1 connector's unused report pipe had a
single 250-ms EOF read. The final source waits up to five seconds, checking
cancellation and the job deadline between reads. Its rebuilt ARM64 worker
test SHA-256 `a7423595f91d8b2cd879448facfc2fbbb81d895c9172d06e23214a3c96423386`
passed 101 default VM tests and the two-family Root-forwarded test. The
rebuilt worker ELF SHA-256
`46222e5a0902d786458e3a47a8e82ada6c6dab9ffd0d7fb56cab29ed8cbb54b9`
completed a new success role `f8b74a8f9fedd0bb` with 24 events and host
tap-journal pin
`267b2834e2c77f7a0c864c34f0a4ebe05c7df8dc5e368036c9e99cc2113f1886`.
After inspecting and removing seven unheld transient `/tmp` test executables,
the VM had 9,055,580,160 free bytes. Six more fresh roles ran on that final
worker digest, with each key pinned before worker acknowledgement and each
tap journal pinned from the completed guest run:

| Final worker role | Fresh run ID | Host-pinned tap journal SHA-256 |
| --- | --- | --- |
| success | `59f657ed0536d244` | `375619d47b3f65b184f2264774d278b88bfd6b42deaf9d03d34c66cb1ece0bde` |
| input-binding | `98e8725a123c1eb2` | `9aec5ad548ad26820577965e85bcdb7f7b49a4a070de14dab7f32d68d94278bf` |
| injection | `bf60214e33b06859` | `7d482e03e385d07ae83588cf85305b9da9f4f3e4d708ceea2782328db07b43ee` |
| boundary | `9230965c86a75e92` | `5be22b63d12f81a59495a64b7ba186c0d537bb4c929b1dbd1f76e72c0d2a267f` |
| timeout | `4a1595b46287deff` | `be0b96f577c49fd8487d4e1a87b67e6e9ca17e6276eb8e49cb79f23396bffe12` |
| cancel | `529608d2e640f37a` | `332cb7220c0e795d701fcfa0e9327214135bfee90f1590c73f275fb1255b31c1` |

The final worker's one-use host v5 suite manifest SHA-256 was
`5342eb9896519202b0329eca7aa9d166487e4a481ed934f60342561d48ad6437`.
The same Root reader matched all six roles, 144 frames, six source-bound docs
records, twelve signed Native proxy processes, 32 physical files, five
absent effects, six cleanup journals and absent cgroups. It again reported
`execution_eligible:false` and no conformance package. The VM finished with
8,962,187,264 free bytes, 372,252,672 above the 8-GiB admission floor.

This diagnostic proves Root observed and forwarded the socket traffic under
the pinned process identities and matched the signed Native transcript. It
does not independently observe product-internal execution of each MCP call
or attribute physical effects to that call. The controller and private cell
are still a draft integration generation, the Lima readout lacks independent
VM identity attestation, and no model inference, conformance package, or PR
gate qualification was produced. The Python observer and passive gate retain
ownership.
