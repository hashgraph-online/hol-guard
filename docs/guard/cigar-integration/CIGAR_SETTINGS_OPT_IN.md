# Ordinary CIGAR opt-in after catalog import

The ordinary settings writer can now enable a verified installed SDK after an authenticated catalog has been imported. The real final 0.14.1 regression first reproduced a false refusal asking the user to set up CPython 3.14 again. That failed result is retained as evidence.

While tracing P7's off-state selection workflow, inspection found that the writer held `config-write.lock` while validating an installation. Versioned installation validation resolves the retained catalog, which attempted to acquire the same lock. The nonblocking acquisition failed, and the general opt-in check presented the busy result as an unverified installation. The installed bytes and receipt were valid.

## Validation and publication

Normal settings requests now compute against an exact configuration snapshot before taking the short writer lock. A new opt-in first checks enrollment metadata so a missing or malformed installation does not provision preparation stores. It then acquires the existing profile lifecycle lease and repeats full native byte/receipt validation outside the configuration lock. That lease excludes conflicting SDK/Python preparation, catalog changes and switching through publication.

Final publication acquires the short writer lane, verifies the Guard home identity and compares the exact configuration bytes captured during preparation. A concurrent edit returns `config_file_changed`; the caller must reload before retrying. A replaced profile directory refuses rather than redirecting the write. The operation does not replay a staged result over a later edit.

Explicit Stop retains the independent access-reduction path and does not wait for the preparation lease. Metadata checks, installed-receipt offline rules, current withdrawals, exact SDK/interpreter/artifact verification and managed settings validation remain in force. The request/result schemas and existing operator approval gate are unchanged. Native catalog/storage/withdrawal/busy diagnostics are preserved, so transient contention does not incorrectly request installation setup.

Saving enabled intent leaves SDK activation to the existing explicit Start action. The settings operation does not create a serving actor, source scope, app grant or background activation job.

## Stop ordering

Native CIGAR preference changes and every explicit Stop write a `context_assistance_intent_revision` marker outside the runtime preference table. Repeating Stop while already disabled therefore changes the exact persisted snapshot. An enable prepared before that Stop cannot pass final byte comparison, even though the typed enabled preference was false both before and after Stop.

The marker is a domain-separated hash chain over the prior configuration and next typed preferences. It requires no counter reset or random source. The native writer owns the field; a settings payload cannot set it. It carries no SDK authority, grant, credential or execution approval. A repeated Stop changes neither effective Guard configuration nor typed runtime preferences, as verified through the native effective-settings loader.

The test-only publication hook exercises competing native writes at this boundary. It is absent from production request schemas and cannot authorize a write or alter a verification result.

## Verification and scope

Five new native cases cover the free short writer lane during preparation, preserving another client's edit, repeated Stop fencing an older prepared write, effective-policy equivalence, caller-owned-field rejection, old/malformed marker continuity and profile replacement. The complete protected configuration suite passes 31 tests with one internal process-loss helper ignored.

A real SDK case uses an exact managed final 0.14.1 installation and external CPython 3.14.10 with a test-only signed catalog. The ordinary `guard-config-update.v1` entrypoint saves enabled intent successfully while Service still has no runtime or activation job. Holding the lifecycle lease refuses the opt-in and preserves disabled settings. Holding the short writer lock reports catalog busy. Injected Python bytes in the disposable installed bundle are rejected before execution, and restoring the original tree permits verification again. A concurrent Stop while already off wins the prepared-enable race.

The original false-CPython refusal, an intermediate SDK pass and the final diagnostic-aware pass retain their separate source/image scopes. The existing active-context/catalog-refresh/re-verification/switch/latest-data-rollback/Stop case passes again on the final image because the persisted Stop path changed. The injected SDK file belongs only to the disposable test slot; upstream SDK sources, published wheels and shared task interpreters are unchanged.

Registry 118, Service 17 and off-state saved-data recovery 10 tests pass separately. Rust 1.88 compilation, Rust formatting and native authority/I/O/privacy gates pass. Clippy retains 36 baseline errors in 23 hash-verified unchanged sources and zero new errors, with two unused production helpers. Python/CLI/HTTP framing remains byte-identical to the prior 76-test checkpoint. Counts overlap other focused suites and are not summed.

[Evidence](evidence/receipts.json) binds exact sources, images, logs, inputs and preservation. This is local macOS ARM64, final SDK 0.14.1, external Python 3.14.7/3.14.10 across the two actual cases and test-only qualification/roots. It does not qualify a real newer SDK, b47380, managed-Python end-to-end, installed/frozen delivery, actual CLI/HTTP-with-SDK transport or other platforms. The native entrypoint is called inside the test image; installed process/transport qualification remains required.

P7 pin/update/notification/channel/retention policies, off-state SDK/data selection and safe removal remain unfinished. Off-state selection needs cold preparation of the coupled SDK/data pair. P8 UI/walkthroughs, remaining P6/P9 crash/cleanup/data-choice and approval-isolation work, production feed/trust, and P10 platform/load/performance/maintainer-bump qualification remain required. The original broker/transport load failure is not proven resolved by these normal-flow cases. The full P0–P10 goal remains active and incomplete. Existing workspace/tutorial work, original integration acceptance/log, live profile/hooks/preview, execution approval code, system Python and upstream SDK remain preserved.
