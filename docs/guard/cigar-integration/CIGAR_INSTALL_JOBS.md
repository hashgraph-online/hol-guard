# Native CIGAR installation jobs

Status: native online/offline acquisition, preparation, private interpreter registration, authenticated installation publication and job recovery have real macOS arm64 source-build evidence. P4 remains incomplete: [private interpreter preparation](CIGAR_PRIVATE_PYTHON_PREPARATION.md) is verified, while durable native setup/discovery, authenticated interpreter publication/full-tree binding, conditional dependency/ABI coverage, job retention/maintenance and user-facing transport/UI work still need completion. [Python requirement preflight](CIGAR_PYTHON_COMPATIBILITY.md) is now native and data driven. No production catalog qualification is promoted by these tests. See [Artifact acquisition](CIGAR_ACQUISITION.md) for the exact public download proof and supported network modes.

The installation worker is separate from the active context actor. Installing or cancelling a replacement does not update `config.toml`, select a runtime, enable a feature, revoke a current pairing or close the current actor. Actual SDK checks use fresh synthetic memory/SQLite domains. They grant no access to user documents or commands.

## Operator and resident boundaries

The native `context-assistance-install-operator --stdin` command accepts `guard-cigar-install-operator.v1`, an absolute private `guard_home`, explicit `operator_approved: true`, and one nested `operation`:

- `{"action":"register_interpreter","python":"/absolute/path/to/python3.14"}` probes an explicitly selected protected executable using the fixed isolated native probe. It stores an opaque interpreter ID and measured final CPython 3.14/platform/ABI/executable facts. It runs no CIGAR SDK.
- `{"action":"import_wheels","build_id":"catalog-build-id","platform":"darwin-arm64","files":{"locked-filename.whl":"/absolute/path/to/locked-filename.whl"}}` imports the complete exact catalog wheel set into the private content-addressed cache. Exact byte lengths/hashes are checked before publication. This does not enroll or qualify a runtime.

Those are advanced local operator inputs. The resident `context_assistance` operation's `versions` kind accepts only these action shapes; paths, hashes, supplied facts, trust roots and qualification flags are rejected:

| Action | Fields | Result |
| --- | --- | --- |
| `releases` | none | Bundled release/checkpoint metadata |
| `interpreters` | none | Registered interpreter metadata |
| `jobs` | none | Bounded historical/progress metadata |
| `job` | `job_id` | One durable job and observed worker state |
| `install` | `job_id`, `build_id`, `interpreter_id` | An idempotent install-only preparation job |
| `cancel` | `job_id` | Durable cancellation intent and the actual job outcome |
| `recover` | `job_id` | Reconciliation of interrupted/uncertain publication |

The existing standard CLI/HTTP/UI does not yet expose this whole workflow. No new feature capability is advertised to older clients before that transport work is completed. Paired context-consumer requests do not receive these operator actions.

## Lifecycle and ownership

Jobs progress through queued, acquiring, extracting, verifying and publishing. Ready means an installation record was committed and its verification runtime closed; it is independent of the active service's readiness. Failed/cancelled jobs retain their precise outcome. Recovery-required state prevents blind replay after uncertain effects or unsafe cleanup.

Every new install resolves Guard-qualified platform data before starting a worker. The bundled final 0.14.1 entry remains upstream-only, so production install requests currently refuse with `native_context_assistance_cigar_guard_qualification_required`. The real tests use a separately signed test-only catalog, exact approved bytes and isolated temporary profiles. Test keys never become production catalog roots.

One private preparation lease serializes installation, interpreter registration, cache import and recovery per profile. Publication separately takes the installation-registry lock. The active actor and native command/approval data plane are not held during SDK work. New bundles are staged privately, verified as a complete pinned tree, moved to a new immutable slot and published only from an actual opaque `VerifiedRuntime`. The slot binds immutable release/artifact/dependency/profile/tree/worker facts and the Python fingerprint; origin, qualification and catalog refresh metadata are excluded. Existing selections and external operator environments are not overwritten.

Job metadata is stored atomically with private protected-file primitives, bounded strict JSON and stable/single-link reads. Reused job IDs cannot change the target. Metadata reads never run Python or inspect SDK trees. In-progress metadata temporaries are recognized so a progress poll does not mistake its own atomic writer for corruption.

`worker_live` is true/false only when this manager owns the corresponding thread handle; it is null when that process-local evidence is absent. A journal entry by itself never proves a worker dead. Recovery first acquires the preparation lease, so it cannot race a worker in another process.

Cancellation persists a separate marker and signals the local worker; its deadline watcher also observes markers from another process. A 120-second deadline cancels optional work. A cancellation after committed publication reports the actual installed outcome. It never undoes a successful installation, changes the selected runtime or restores old SDK authority silently.

Recovery checks the authenticated installation record and actual artifact fingerprints before treating an uncertain publication as ready. It does not replay SDK mutations to guess what happened. Before publication, cleanup is limited to this job's marked private roots, with bounded traversal and no symlink/hard-link/special-file following. Every registered alias/reference and the selected installation protect their bytes. Unknown ownership, unsafe contents or incomplete cleanup retain recovery-required state.

Current bounds: eight installations, sixteen registered interpreters, thirty-two durable jobs, a 512 MiB / 512-file cache, existing 256 MiB expanded bundle limits and 500 ms cleanup traversal. Job pruning/removal and broader maintenance UX remain follow-on work rather than an undocumented unbounded history.

## Exact source-build evidence

[The saved job proof](evidence/receipts.json) binds the executing native test image, source-file fingerprints and test log to the exact final 0.14.1 SDK, protobuf 7.36.2 and CPython 3.14.7/macOS arm64. All 25 registry/job tests pass, including two real scenarios:

- An inactive managed installation is verified, owner-authenticated and published without enabling/selecting it. Repeated requests converge on one job/installation. A deliberately uncertain publication boundary is reconciled from the actual record and bytes without replaying the SDK doctor.
- An explicitly enrolled current final-0.14.1 runtime stays ready while a replacement runs every synthetic feature check. Cancellation at a test-only barrier before publication closes the replacement, removes its partial slot and preserves the current actor generation and exact configuration bytes. The barrier exists only in test builds. This is install-only continuity, not a b47380 candidate-to-final switch or a real newer-version upgrade.

The tests measure status latency only for these local synthetic workloads. They do not replace installed/frozen, hook/approval, transaction-crash or broader performance acceptance. Real process-crash injection across every future switch boundary remains pending; the lost-reply test deliberately recreates one durable publication boundary.

Full production runtime typechecking passes. The broad native Clippy run stops in untouched `guard-command` code with 35 existing lint errors under Rust 1.99; that baseline is not hidden or described as clean. Original source/compiler warnings are retained.

Exact public acquisition now has [recorded native evidence](evidence/receipts.json): all 32 registry/job/acquisition tests pass for that recorded source. The subsequent [Python compatibility receipt](evidence/receipts.json) passes 33/33, including a pre-job later-patch refusal, public wheel/tree proof and both real SDK scenarios. The earlier 25-test receipt remains historical evidence for its exact source/test image. Next work remains Python setup/compatibility data, explicit qualification refresh/historical slot reuse, maintenance controls, data preparation, serialized switch/rollback and fresh authority, operator transports/UI, and installed/frozen/platform qualification. Production catalog trust/hosting and a genuine newer-version artifact remain explicit external prerequisites where required by the full goal.
