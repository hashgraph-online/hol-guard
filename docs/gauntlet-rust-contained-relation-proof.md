# Contained-effect relation proof

The Rust reader joins a held final file and a kernel-observed Native writer to
the signed contained request, Pre/Post decisions and result for one retained
control. It reports `request_to_writer_causality_verified:false`,
`guard_causality_verified:false` and `execution_eligible:false`.

The reader implementation was checkpointed at `a89088c5`; the ARM64 artifact
below was compiled from `40df55fb`. Its six implementation files are unchanged
through test source `da6d899b`. Five contained-relation test groups and the
three existing signed-product tests pass in the repository on macOS and
Linux ARM64. Both suites share the original synthetic product fixture, and
the ARM64 workflow now selects both explicitly. The new cases cover all four
positive roles, internally consistent re-signed wrong Pre/Post decisions,
transplanted outputs, duplicate records, run/key/schema changes, writer
identity and opaque file generations. These are synthetic verifier tests.

Warnings-denied ARM64 Clippy, Rustfmt, all 51 Gauntlet CI policy tests, merged
Native library/CLI compilation and the ownership-scope report also pass
locally. The child imports upstream `main` at `4a654ea8`; the reviewed source
map contains 427 files, with 58 changed and seven added relative to the
unchanged Python baseline. Python's actual bootstrap selection and Rust's
install plan independently agree on 396 files, 407 entries and new controller
digest `28fd562fa80d0ed626d9732da75590273a0a9b2c8b815df8fcabb228d1de2c8b`.
This digest describes a fresh install of the current source; it does not
replace the older retained VM controller digest `01ba1750…`.

## Retained live readback

The diagnostic ran on `hol-beta-bootstrap-20261016-004`, with 2 vCPU and
16 GiB RAM. It read retained evidence and made zero model requests. Candidate
source `76c31929833b5571d25a56d9783e24a0997d5422` reports version `3.49.0`;
this is the previously modified candidate, rather than a fresh test of current
`main` or an unmodified release wheel.

| Input | Outside pin |
| --- | --- |
| Build | `b70d59e2681c4a3f` |
| Run | `3da328ac01870040` |
| Reader artifact | `62e02107198bc1957b741788103937b2a8c051585f668c4491b7340186e3a4fd` |
| Worker generation | `1c8a37cd56b5f91fb25ea8f3e17003e5dbacdffddd14e45cb9cd628d6ac553aa` |
| Started marker | `649968ea0571f225189dfd9b2d6392244ce3f9c643a213f5cf00b8031d23bb20` |
| Config | `8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492` |
| Private manifest | `66703091ba2f7815341aa0a3535de1c52c35ec3a170c2348975ef8704a1ae2d5` |
| Installed prefix | `67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28` |
| Report | `88c22e0058cc7d7ce000487f686e4a588fb046b54d22c53458291e7ec35b0f4e` |
| Effect journal | `c7247324aade227887d36241f02b2ceb70b2c896c46e332095985a36d0ebf308` |
| Signed control | `dc36ab8761094b1664b59fee1ab9dcb6704c00db7cd22204ea9df44101986adc` |
| Native asset | `533d72c30de62b460556c7330067e1078b353b094ee2fc3f1edf0f6d6af83eed` |

The self-checking Root reader verified the keyed started marker, pinned report
and v3 effect journal under the exclusive worker lease. It opened the fixed
`native-contained.txt` through held no-symlink descriptors, checked the kernel
idmap against the checkout directory, and rechecked the visible paths,
descriptors, report and journal before returning. The control context retained
its full v7 config, controller, private-cell and 13-role asset checks; the
Native asset hash agrees with the signed runtime and captured writer image.

The final file contained exactly the 20 bytes `private plane effect`, with
SHA-256 `93313832ed89058af22413b62b883ac6225572fc7e1b7551e8c224893ba542cc`,
device `64769`, inode `3466694`, and kind-1 opaque handle
`c6e53400d4fa30b8`. Physical UID/GID were `10001`, mode `0600`, with one link.
Exactly one close-write matched that held object: event `4948`, writer PID
`1440453`, start tick `43526094`, and namespace PID `64`. Its post-event image
reported `serve-managed`, the pinned Native executable, and three namespaces
matching the product sample. The product init was PID `1440390`, start tick
`43525634`; the writer's cgroup was
`/holgauntletrust3da328ac01870040.slice/hol-product-cell-b3727ab6878e48d098ee4c2df9a1c1b5.service`.

The signed request/result relation matched one prepared, consumed and completed
route, the fixed SDK call, the expected sandbox-required Pre decision, and the
Post decision reviewing the captured result's exact output digest. The signed
product relation matched the independent product PID/start, six namespace
inodes, argv and mountinfo hashes, and all three task mount maps.

The compact readback is retained privately as
`3da328ac01870040.contained-relation-62e02107.json`, SHA-256
`53087b8a0a2b9fa9726434b12269a328a4057e8e3dee81f0bd93fe23d5ad65f9`.
Six live changed-input cases refused: reader hash, started-marker hash, report
hash, journal hash, control hash, and a different role. Their calls did not
change the retained control or consume model quota.

## Remaining boundaries

A post-event process image identifies the executable observed while its pidfd
was held. It does not identify the image at the instant of the write. The
request, decision and output records remain controller-signed observations;
this reader does not independently authenticate the Native MCP frames that
preceded the write. It therefore cannot establish request-to-writer or Guard
causality, score a control, or admit execution.

Only success has live v3 composition evidence. The four positive roles have
synthetic relation coverage; timeout and cancel are refused by this reader.
Other physical effects, deletion/replacement, remaining unknown writers,
independent request/frame observation, fresh current-source conformance and
actual inference remain open. Historical v1/v2 records retain their original
meaning and are not upgraded by this proof.
