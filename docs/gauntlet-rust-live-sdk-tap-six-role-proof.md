# Live six-role Rust SDK tap staging diagnostic

Code pin: `6a1016247c5c459414f265d2f89130f7ccd32dc9` (2026-10-21). This
change adds a one-use macOS host pin for completed tap journals, a read-only
Linux ARM staging-readiness command, and an opt-in Rust suite reader that
compares each Root tap journal with its signed Native MCP trace. The v1
worker, Python observer, dashboard and PR gate were not cut over.

The candidate was the retained patched local source
`76c31929833b5571d25a56d9783e24a0997d5422`, build slot
`b70d59e2681c4a3f`, version `3.49.0`, provisional config digest
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`
and prefix digest
`67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`.
The 36-file private-cell source-map digest
`909592fac5403f683df5673f5f195eac014986e91d50e547b7c214871507ae54`
matched the retained private manifest
`66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5`.
The read-only ARM64 staging preflight passed all 13 declared asset roles,
found the contained completion and 407 controller entries, and reported zero
missing capabilities and zero model requests. It remained
`execution_eligible:false`.

The source-matched controller came from Git commit
`b9932457dcab9e3a10ea93d9641ac927c6bd651d`: all 427 archived
`ci/gauntlet` files matched the source map; the independent Root installer
created `/opt/hol-gauntlet/controller-b9932457dcab9e3a` with 407 entries and
tree digest `eb1c9f9de6e936f072d368bfbc6fa8e8cf4f563407eecf19f7a10a866f1cfa44`.
A separate Root verifier matched all 3,650,476 installed file bytes. The
installed v2 worker SHA-256 was
`8663263f07e4be028c9527397a6e3b5d1c07d311ad2270b9e89596c55659c814`;
the UID-10001 tap child SHA-256 was
`9795ed69a34ff66c5fcf7a3f12581267d5ea445689b12e0385a2ce35e3957bf7`.
These are draft integration artifacts, not independently approved production
trust anchors.

The macOS host issued six distinct one-use v2 prelaunch keys and received
six `invalid-evidence` terminals after live candidate Bun and signed
controller execution. Every run captured docs and mail sessions, 24 Root
tap frames, one SHA-matched Bun executable, and a completed cleanup report.
The host then retained a 0600, fsynced, one-use tap pin tied to each
prelaunch key, keyed terminal, report and exact journal digest. The first
role used bounded private staged transfer files; the other five used the
fixed Rust Lima readout command. Replay refused. The Root journal for each
role was 10,018 bytes.

| Role | Run ID | Root tap journal SHA-256 | Host tap pin SHA-256 |
| --- | --- | --- | --- |
| success | `d6aaeb3b55e0d477` | `bcfccedc327f8954a4cdddf0465a4cc2a8052e7914e1e89e79d990c50f628756` | `53fab77c59eba37c0ca15a5b8ec405c0c13f95db5ef3f019f370e6bb413ee829` |
| input-binding | `0f590a4a357de5f7` | `c130bba71a2c7eee9504133686cbe73fc144b7dfe665452dbbdb7ead2ca0fe1d` | `8886f5998f5280b7b1e30dfed49edadd3ba7fc84807424a9498117be1a51d20a` |
| injection | `9929ebeed73a41dd` | `f85019ded9ca551fe4a1913d63bc31938decd9cc389249143397df8bc32a68ac` | `b2303c3cdaa6fc0b6121b5ebeba8bcb2ae69fc3ee3b1d17c425c999e4b141a64` |
| boundary | `4c4d0b307168b89a` | `6c2149a495f51598d49548a49302b7719aa887daaa74e9f9816077f262ca4ec4` | `5be820b0d306c3ac69cd8dbbedaf58b502661b88df769c8325f208ba475c1303` |
| timeout | `dc2b7aa4d1232ce4` | `7d9c66e023309bcb12582b1b809a3d9abbff14628944aa9ab2bffda60ba57a1d` | `0f6743df4e8f2e8c44af4fbbc45130f71fddc53f85d957e9cb3f1007a03f82e8` |
| cancel | `21a89885d564820c` | `66f268069b73ef4a52dedf195bf2f5a1197833c5bedf058ec198d8db6dd3edf5` | `7e507e74bc290694cb852f94b1c4670b29020753c75f0cff6a3154de5844e88d` |

The one-use host suite manifest SHA-256 was
`1e5a96ead9346bc0b4f3b534b6665856900d0bd2368f7c925e98048569937885`.
The prior v5 reader accepted all six roles without Native MCP mode, then
rejected `--require-native-mcp` because it required global adjacency between
a `frame` and `delivered` event. In the live trace, a docs frame was followed
by mail events before its matching docs delivery. The corrected Rust reader
requires adjacency within each session, retains global sequence and exact
frame/message matching, and refuses changed or missing pairs. Its
SHA-matched ARM64 binary accepted all six Native boundaries and 12 proxy
processes. A regression test exercises permitted cross-session interleaving
and refused same-session interleaving.

The later [mount-isolated six-role rerun](gauntlet-rust-sdk-tap-mount-isolation-proof.md)
found a valid response-frame/client-notification interleaving within one
session. The current reader allows traffic in the opposite direction while
still requiring each pending frame to match its forwarding or delivery
event exactly; the adjacency statement above describes this historical code
pin only.

The final optimized suite reader SHA-256 was
`4274eb15dcbb6b00a980e18a569e2ee5f06244609fad9d30be05ebea15ebf9b3`.
With the six outside host journal digests in role order, its new opt-in
`--require-sdk-tap` mode returned six matched tap journals and 144 matched
frames, alongside six signed records, six sampled agent/gate/Bun identities,
six Native MCP product boundaries, 12 signed Native proxies, 32 retained
physical files, five absent effects and six cleanup journals. It matched
each tap relay PID/start/cgroup to a kernel sample, its Bun ancestor to the
signed gate process, and its Root peer to the keyed terminal. Tap frame
canonical message digests, method and ID matched the signed Native trace
in family/direction order. A wrong outside journal digest was rejected.
All 18 controller/product/tap cgroup paths were absent after the runs;
Podman listed no containers. The VM had 8,995,352,576 free bytes at the
post-run check, above the 8-GiB floor.

The ARM64 evidence unit binary passed 49 tests; native macOS host library
tests passed 12; warnings-denied ARM64 evidence/worker and native host
all-target Clippy passed. Rustfmt and `git diff --check` passed.

The host pin authenticates byte consistency after the prelaunch key, but
the five fixed Lima readouts still use guest `cat` without independent guest
file metadata, executable or VM attestation. The Root tap journal records
reparsed child pipe frames; it does not independently prove the child
forwarded them to Native. Root constructs Native-peer metadata from its
controller pin after the child checks the peer, rather than observing that
socket itself. The child has a separate UID and cgroup but not separate
PID/mount namespaces. Physical product effects and Guard decisions are not
independently attributed to those frames, and no source-bound conformance
package or live model inference was produced. Every terminal and suite output
remains `execution_eligible:false`; PR-gate promotion remains blocked.
