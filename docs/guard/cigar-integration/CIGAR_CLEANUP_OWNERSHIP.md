# Lifecycle ownership while SDK cleanup is pending

The native switch worker now retains its original profile lifecycle lease until every cancelled actor acknowledges cleanup of both its SDK process and private host state. Inactivity or an expired 500 ms cleanup observation does not release ownership, cancel a journal transaction or permit data pruning.

## Native lifetime

A fixed native array holds at most one actor for each of three roles: the unpublished candidate, the stopped source and an unpublished failed reconstruction. Only those native construction/close paths populate it. The handles contain no serialized authority and are never accepted from requests or restored from disk.

After bounded cancellation/close, a missing acknowledgement records cleanup_pending and waiting_for_sdk_cleanup. The same worker keeps Owner on its stack and polls only atomic cleanup facts. It performs no SDK work, source admission, config publication or repeated SDK mutation while waiting. The short settings writer lock is not held. Status and native Stop remain independent; cleanup_pending is projected from live cleanup metadata as well as durable job progress.

Other installers, interpreter jobs, switch owners and full saved-data removal cannot acquire the profile lease. Another Service instance does not bypass that ownership. After acknowledgement, private handles are released, and the worker may cancel/prune an unpublished precommit candidate or attempt the already-checked fresh source reconstruction. A reconstruction whose own actor cannot clean immediately is retained under the same lease as well.

Successful target/source publication keeps its serving actor out of this cleanup set. Normal late upgrade cancellation cannot cancel a published runtime. Stop/config/shutdown still revoke native authority and both SDK cancellation tokens, preventing any reconstruction attachment.

## Budgets and pending state

Preparation and reconstruction SDK cancellation budgets remain 120 seconds and at most 30 additional seconds respectively, with the existing absolute restoration cap. Existing SDK request/actor deadlines remain unchanged. Waiting for destruction is not an extension of those SDK budgets: the SDK is already cancelled and no work is retried.

Private destruction cannot safely be declared complete by timeout. If acknowledgement never arrives, the live job remains cleanup_pending and retains its lease; further lifecycle mutations report busy while status and Stop respond. This is explicit pending ownership, not a promise that arbitrary blocked host destructors finish on a clock. Process-loss/restart reconciliation and the complete cleanup/crash matrix still need qualification before public controls ship.

## Actual SDK evidence

Two saved-mode actual SDK tests deliberately hold private Engine destruction after runtime.close. They exercise all three roles with finalSDK0.14.1, an enrolled source, a test-only qualified exact-wheel target and external CPython3.14.7/3.14.10 on local macOS arm64.

The candidate case keeps the original source serving reviewed context with unchanged actor, native epoch, generation and config while candidate cleanup is blocked. Its prepared data remains until acknowledgement and is then pruned. The stopped-source case verifies another Service and saved-data removal cannot acquire ownership, then releases the destructor and observes fresh reconstruction with the complete original reviewed vector. A separate Stop during that pending state returns before private cleanup, remains disabled and prevents rebuilding.

The failed-reconstruction case constructs a fresh source SDK, installs a private destruction gate and issues native Stop before attachment. The unpublished new actor remains owned while its destructor is blocked. Status responds and saved-data removal refuses. After acknowledgement the lease is released, no runtime is attached and disabled preferences remain disabled.

The destructor gates, weak candidate inspection and post-construction hook exist only in test builds; production Engine/Signal contain none of them. The new progress enum is appended, preserving existing request serialization/fingerprints and earlier phase numbers. No old acceptance assertion, SDK deadline or mutation-retry policy is weakened.

These are local same-SDK ownership/data tests, not b47380/newer-SDK, managed-interpreter end-to-end, installed/frozen, all-platform or complete process-loss acceptance. Finish the remaining crash/unknown-write/Stop matrix, retained-generation source reconstruction, durable interrupted erasure and per-scope retained/prepared-copy deletion, inactive data/lineage/capacity and accepted feature/data transitions. P7/P8 controls/catalog/update-policy/UI and P9/P10 final qualification remain required. The full unbudgeted P0–P10 goal remains active.

[Evidence](evidence/upgrades-cleanup-ownership-20261027.json) binds exact source/image/log state and qualification limits. Original acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history remain unchanged.
