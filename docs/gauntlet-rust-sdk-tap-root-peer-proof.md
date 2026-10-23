# Root-side SDK tap peer checks at every reported frame

The opt-in staging worker now reparses each child-reported SDK/Native frame
only after its Root owner rechecks the actual held SDK socket peer and the
Native socket passed through `SCM_RIGHTS`. Both Root-held peers retain a
pidfd, PID/start tick, UID/GID and cgroup relation. The bounded pipe reader
accepts a per-frame callback; its existing public reader retains the same
byte and JSON-RPC contract for other callers. A focused test counted two
callbacks for a request/result pair and refused a changed peer on the second
frame. This supplements the existing UID-10001 child's own process checks;
it does not authenticate the child's claim that those bytes were forwarded.

On the dedicated Linux ARM64 VM, the SHA-matched optimized worker test
binary `e0d33d7b44bd12bac89c9eaaeb7e54a6bb70b42881efa9b3a57aeb066d9a6fbd`
passed 98 default tests with 12 intentional fixture ignores. Two separate
Root-only tests passed against the retained pinned tap child ELF
`1a4bf073275aac1114e373d28735af1b717f32f38000fe991a734522a40bf089`:
a real UID-10001/Root docs socket exchange and a concurrent docs/mail staging
handoff with journal and cgroup tombstones. Warnings-denied Linux all-target
Clippy and macOS all-target `cargo check` passed.

The optimized live staging worker SHA-256 was
`767988ad15d2e544a5e91bf35e62be8d49ae3062e41224e8da73d27f6a36cf22`.
Its Root:Root, mode-0500, one-link VM installation matched that hash. It ran
two fresh one-use roles against the retained v3.49 candidate and pinned
controller generation `7364fbc27dc95d0de97c2d9ec157fbb54f832fdb`.
The first host launch refused before recording a pin because the binary was
under a diagnostic filename rather than the CLI's fixed digest-derived
path. The same verified inode was moved to that path; the retry then ran.

| Role | Run ID | Signed control SHA-256 | Root tap journal SHA-256 | Host tap pin SHA-256 |
| --- | --- | --- | --- | --- |
| success | `cb5a31e79a23d640` | `d2081d0bf91ddbda0912ecb256113fec598b54ead562b97709297281c4550766` | `9a5a01be9759bf9664369461a89c51262b8ebac865864df0c6a6dbe8f34f9903` | `43d0aaf4643721a6878c1a5a873b43c0d679c8908f3eae70dc57bc2da8c221ba` |
| timeout | `f9b74e2c8d105a63` | `b405ec4cb43886163f407481e36d5448b8c2af0aa4ea46b9c56c8c1b76638e33` | `596e6f80d9f1849248c9c4da7b643cb7e94e00df5eeee8ca347a22a1c03d69e7` | `8262ab2464ec7cacf575885d4652dd7673aa0c287e81cce0e0a08173ab354352` |

Both host commands exited zero, then the one-use host tap-pin command read
back each Root journal, keyed terminal and report. Each journal had 24
events, two sessions and 13,956 observed wire bytes. Each worker report
recorded exit zero, cleanup and `record_scored:false`; Podman had no running
containers after the second role. The VM had 8,774,455,296 free bytes, above
the 8-GiB admission floor. These two roles are a timing diagnostic for this
new worker; the earlier [six-role mount suite](gauntlet-rust-sdk-tap-mount-isolation-proof.md)
still uses its own older worker digest. No six-role manifest or conformance
package was constructed from this two-role check.

A disposable Root VM probe also ran `unshare --pid --fork --mount-proc` and
saw only PID 1 in its new `/proc`. A separate inherited Unix socket pair
showed the nested child as PID 1 but translated its external Root peer's
`SO_PEERCRED` PID to **0**. Thus the current child-side PID/start/cgroup
authentication cannot simply be carried into a PID namespace. A future
isolated-child launcher must move the authoritative peer checks to the Root
holder, retain a pidfd for the actual nested child, and prove bounded
termination, restart reconciliation and no host `/proc` access. This proof
does not establish that redesign, independent Native effects, Guard
decisions, model inference or execution eligibility.
