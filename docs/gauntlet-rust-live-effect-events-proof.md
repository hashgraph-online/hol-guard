# Live Root staging effect-event custody

On 2026-10-22, the opt-in Root-relay staging worker captured Linux ARM64
`FAN_CLOSE_WRITE` events throughout four fresh v3.49.0 deterministic controls
on `hol-beta-bootstrap-20261016-004` (2 vCPU, 16 GiB RAM, 48 GiB disk). The
candidate source was `76c31929833b5571d25a56d9783e24a0997d5422`, the
controller generation was `7364fbc27dc95d0d`, and its complete installed
tree digest was `01ba175093b9e9a7a114eedde2c213e9254426f079c8ec0c2b201b9ff2f0c4ec`.
The host prelaunch key pin preceded each launch. These are retained candidate
artifacts in a draft integration branch, not independently reviewed production
installations.

The worker starts a Root fanotify mark before creating the one-use cgroup and
launching the controller. A dedicated one-millisecond observer drains it
through controller and descendant cleanup, then writes a Root-only, fsynced,
one-use canonical journal under the keyed started marker. Each row records
the final file device/inode/owner, kernel-reported PID, whether a pidfd was
available, and a live PID/start-tick/cgroup tuple if sampling succeeded. A
missing writer stays unknown. The report and terminal bind the journal
receipt; all four producer runs remain `invalid-evidence` and
`execution_eligible:false`.

| Role and run ID | Worker SHA-256 | Events / unknown writers | Effect journal SHA-256 | Host effect pin SHA-256 |
| --- | --- | ---: | --- | --- |
| `input-binding` `b7d9daabcc785762` | `9557cfdc38bd643ef7347431d9fbb21e82414fb462d5e0c34820c4cb82da586d` | 5,433 / 400 | `fe8ba670f7188a120d55cd6e90f26049cd4f9edfced4fad712c88e9e1525e83d` | `bd8612e3cd40e9fcfdd30c887dcabe4e1bbe348e986a99168da8eb1db13b2e67` |
| `input-binding` `cda32c146f28704b` | `a7804ec177cc9aa48a12dbd96b80264de7cbe638ef2fe7516cc39c8857c481d9` | 15,049 / 163 | `b60eb3395be8207ade3e0d94692fd8b9082f830046aad810f40f2413712f6674` | `384bc20883943e52faeb6476892f38e48ebae97f3b0ea3d0d53a2c6676a7d78f` |
| `success` `1ec56d984caf72b0` | `8a9ee8922ff4af798ec7560de714cb3f48f18ccaf3a78374cc15e53b00fcfb95` | 9,570 / 149 | `c1a83bc823dfe6ef8f7359b48842ce1be66a75d7fd91673a15bee6a907d83ecb` | `2e2bf6e8c1fb95eb65ad3e60e9447388b7d6746dd996d430740b7580543fef5f` |
| `injection` `8c425d7e1a09f3b6` | `94f1498250b0f223e6b891763ace243b61504fda3b19cf795e2f3e507d930c2a` | 10,848 / 152 | `c78241b27ca3c4e023a45b03f18b7d6d05e9cc028e34a3a6ec8921f5ba9b6052` | `1ebe4dab18364880aa22fe5b85559054ca0006069a2235e73d3d2487f953e557` |

The first run drained the watcher at the worker's 20-millisecond control
poll. The other three used the dedicated one-millisecond thread. The raw event
count also changed, so the lower unknown count is an observation, not a
controlled measurement of observer speed. The second run came close to its
16,384-event cap. A later `success` trial raised the declared event cap to
65,536, but source review found that its canonical parser also has a 16-MiB
and 500,000-node bound. The final source aligns the event cap to 32,768 so
the maximum known-writer row count remains below the node bound; the byte
limit independently fails closed. The fresh final-cap `injection` run retained
10,848 events in 2,866,192 canonical bytes.

For `cda32c146f28704b`, Root `stat` of the retained final-file paths selected
the device/inode pairs for this diagnostic. The captured rows for `native-contained.txt`
(seven), `node-runtime-control.json` (six), and both provider-control files
(one each) all named the same product-cell service cgroup with a live writer.
For `1ec56d984caf72b0`, the node-runtime file (three) and both provider
files (one each) likewise had only product-cell writers. Its
`native-contained.txt` had nine writes: eight from the product cell and one
from an agent container, so the strict same-cgroup correlation must reject
that file. For the final `injection` run, the node-runtime file (five) and both provider
files (one each) had only product-cell writers. `native-contained.txt` had
eight product-cell writes and one controller-job write, which also prevents
strict single-cgroup attribution. Each run's `sdk.stdout` had one unknown
writer and several different known cgroups; it also cannot pass that strict
correlation.
These are inode/cgroup observations; they do not prove which MCP call caused
each write or whether HOL Guard made the intended decision.

The new macOS `gauntlet-host-effect-events-pin` command reads only the three
fixed guest terminal/report/effect-journal paths through the compiled Lima
target. It requires the canonical journal schema and every row, matches its
digest and counts to the report receipt, matches run/source/key identity to
the already durable prelaunch host pin, and writes one private, fsynced host
digest. Its `--verify` mode rereads those guest files after restart and
compares the retained host pin without rewriting it. The final `injection`
run's pin and `--verify` both returned the same
`1ebe4dab18364880aa22fe5b85559054ca0006069a2235e73d3d2487f953e557`
record. The existing SDK tap host pin recorded 24 frames per run and its
separate restart reader returned `verified-ineligible-terminal` for all four
runs. The final VM had 8,767,598,592 free disk bytes, above its 8-GiB floor.

The isolated ARM64 VM ran the one-millisecond observer's 104 default worker
tests with 23 intentional ignores, plus the selected Root-only observer and
journal tests. The final aligned-cap worker then passed the fresh live
`injection` run. The macOS host library ran 17 tests, including wrong row/receipt and
one-use/refusal cases. Warnings-denied Linux ARM64 Clippy passed for worker
and host code. The macOS Rust 1.88 toolchain has no Clippy component here;
macOS host compilation, library tests and release CLI build passed.

This is passive diagnostic custody only. The filesystem-wide mark observes
unrelated writes, cannot identify deleted files from a later final-file
descriptor, and does not capture create/delete. Some short-lived writers
remain unknown. The Lima/guest readout does not attest VM identity; the
controller, worker and private-cell artifacts still require independent
review. No independent Guard-effect scorer, six-control verdict, fresh
conformance package or model inference is produced by these runs. The PR
gate remains passive.

The later [held provider-effect diagnostic](gauntlet-rust-fixed-effect-file-proof.md)
matched both fixed provider-control files in the retained `injection` run to
their journal rows and physical bytes. It remains ineligible because live
idmap attestation and Guard causality are still absent.

A separate macOS `gauntlet-host-staging-effect-restart-readback` command now
requires the durable host key, SDK tap pin and effect pin to share the exact
terminal/report hashes. It invokes the SHA-named Root tap restart reader,
rereads terminal/report/effect journal through fixed Lima paths, and rechecks
all three host pins before returning. Its release SHA-256 was
`4485cd47af2e4af311d527171458aaa9027e447fafc6ee63c89ad0d4951eb8c0`.
All four retained effect runs returned `verified-ineligible-terminal` with
their original 5,433/400, 15,049/163, 9,570/149 and 10,848/152
event/unknown counts. This establishes joint point-in-time custody, not
independent VM attestation, repair or a Guard verdict.
