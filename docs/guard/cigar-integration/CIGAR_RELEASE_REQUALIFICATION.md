# Reusing an installed CIGAR build

A compatible qualification or catalog refresh can reuse the installed files and
installation ID. The current SDK can keep serving requests while a separate,
isolated verifier checks that installation. A release label is not sufficient
to select or replace bytes.

## Identity and compatibility

SDK versions use canonical PEP 440. Native core labels and upstream release tags
are independent, bounded exact labels; they are not normalized or used for
ordering. An SDK preview still requires preview consent even if its catalog
entry is incorrectly labeled stable. Upstream URLs stay confined to the named
repository and exact locked filenames.

An archived receipt survives catalog omission. Reusing an existing build ID
with contradictory worker, SDK/dependency lock or package-tree identity is
refused. Refreshing origins, qualification or optional compatibility annotations
does not replace the same files. Withdrawal remains a refusal.

## Native operation

The existing install request carries only a job ID, approved build ID and
registered interpreter ID. Under the preparation lease, the native owner finds
an authenticated installation with the same immutable SDK, dependencies,
adapter and full interpreter identity. It preserves older managed-slot
derivations and opaque installation IDs. It prefers the selected matching
record, then the canonical slot, then a deterministic ID. An unrelated record
does not determine whether the chosen record can be refreshed.

The job reports operation `verify` for reuse. A new job performs explicit
reverification; retrying the same job ID returns its durable result. Job bounds,
deadline, cancellation, machine policy and ownership checks remain in force.
The installed package tree and registered SDK work directory are not written.
The verifier uses a separate job-owned scratch directory and synthetic inputs
for graph, sharing, persistence and execution qualification. Measuring a feature
does not enable it or grant access to a user's files, applications or agents.

Only after those checks succeed does native publication replace the receipt.
It compares the complete previous record under the registry lock and checks
the actual artifacts and current policy immediately before the atomic write.
An authenticated job marker binds that write to the particular refresh. The
receipt records the catalog checkpoint, qualification identity, measured
features and producing Guard image. Existing paths and selection stay intact.
A reduction in qualified features requires a separate transition; it cannot be
smuggled into receipt refresh.

Cancellation before publication preserves the old receipt and current actor.
A lost publication reply is reconciled using the authenticated marker and exact
target metadata, followed by artifact validation. A preexisting record alone
cannot prove that this job committed. Another explicit receipt update produces
a recovery conflict and is preserved. Recovery does not replay SDK probes.

## Verification and remaining scope

[Recorded evidence](evidence/upgrades-requalification-20261026.json) covers the
exact published 0.14.1 SDK and its locked protobuf wheel in disposable native
macOS arm64 profiles, including historical IDs, cancellation, old-SDK responses,
unchanged package inode/mode/mtime inventory and lost-reply reconciliation.
Synthetic tests cover independent preview/core labels and conflicting immutable
identities. They do not constitute qualification of a real newer SDK.

Production SDK and interpreter catalog entries remain `upstream_only`.
Qualification used by the actual-artifact tests is explicitly test-only. This
work does not implement selection switching, data migration, public CLI/HTTP/UI
controls, pruning, production catalog hosting/trust, installed/frozen acceptance
or other-platform qualification. The full upgrade goal remains active.
