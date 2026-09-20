# Bounded workspace request and receipt observation

This component fills one missing RSP-128/129 observation boundary: it joins
an explicitly declared request to the native wrapper result, delivered
response and complete validated SQLite receipt. It reuses the current
publication observer and ACK barrier; it does not create a policy cache,
change publisher readiness, replace the native result, or change a deadline.

Enter the actual `ReceiptWitness` before `WorkspaceRequestObserver`. The
latter captures and forwards that exact installed native-review callable.
Its `probe(index, workspace_index)` calls the existing authenticated
`_request` once with the declared workspace and a bounded, unique
`mixed-policy-N` attempt ID. The fixture must own the canonical root,
guard home, daemon, writer and all declared workspace directories.

After the fixture's original bounded writer drain, close the request
observer and reconcile the receipt witness with `verify_all=True`. Then
call `join` with the accepted public mutation's monotonic return time,
the actual authenticated target snapshot, expected action and every
declared request index. The publication chain uses its own original
observer clock origin. Preserve that already matched chain and its
publication ID alongside this result; do not substitute a transport reply
for the production committed barrier.

The result distinguishes two observations:

* The earliest native wrapper completion after acceptance among the
  complete declared request set.
* The earliest such completion whose request offer and native-wrapper
  entry both occurred at or after acceptance.

A request offered before acceptance is not relabeled because it completes
later. Negative acceptance-to-offer offsets are retained. Equal completion
timestamps retain all ties and cannot prove a unique first completion.
Every declared attempt must have one observed native call, validated
receipt, writer admission, matching delivered decision, and a matching
committed receipt. Missing, duplicate, mismatched, late or in-flight
observations keep the result incomplete. Calls outside the declared set
are counted separately; this is not a first-decision claim for all daemon
traffic.

The native completion timestamp comes from the existing receipt witness
after the original Python native-review callable returned. It is not an
internal Rust decision timestamp. All timings include observer overhead;
no headline latency or installed qualification is granted.

Authority readback and the sequential SQL count/getter/count observations
run on the controlling caller, outside the native hook call. When the
separately supplied SQLite VFS observer is present, these operations use
its explicit readback scope. They are not writer I/O, atomic transaction
commit timestamps, kernel fsync counts or physical storage byte counts.
The receipt itself must pass the product's complete privacy/identity
validator before capture and again at comparison. Full receipts are kept
for independent identity verification, with the existing 16 KiB per
receipt bound and at most 32 declared requests. No SQL text, hook payload,
workspace path or key material appears in the result.

The owned wrapper is restored only if it is still installed. A later
owner is preserved and completeness is refused. HTTP and native calls
have separate in-flight counts: an HTTP timeout cannot hide a native call
which continues afterward. Closing the observer does not cancel work or
extend its deadline. The caller retains responsibility for the daemon,
writer and process lifetime.

The three new finite test modules use the actual receipt validator,
SQLite receipt schema/store mixin, public getter and `ReceiptWitness`.
Native and HTTP calls are synthetic controls for argument/result/exception
forwarding and timing/identity falsification. These tests do not execute
a Rust runtime, authenticate a real published policy image, or qualify a
workspace campaign.

The incoming `3780ad899ad6c42c91049b2a15fef138e911443f` source reports
local Linux/Python 3.12 validation of 90 workspace controls: 62 pure joins,
16 forwarding controls and 12 lifecycle controls. Its source report also
states that the same process passed 54 writer, mixed-witness and persistence
regressions and 24 compiled SQLite VFS controls, for 168 passes with no skips.
Those are incoming author-reported results; the integration packet preserves
the original text but does not include the original execution logs for that
claim. They do not establish validation of the combined source. The separate
retained `0509` run passed the earlier 88 workspace controls and 264 phases
on its own pinned source. No pass is transferred across this merge.

The two additional lifecycle controls cover a retained native call starting
during committed readback and a closed receipt witness being mistaken for
active instrumentation. They preserve the existing forwarding and cleanup
requirements and need fresh execution with the combined providers.

Two distinct lifecycle diagnostics coexist:

* `scripts/native_slo_workspace_lifecycle_runner.py` retains the incoming
  five-scenario sweep for lost metadata hints, command-key rotation,
  first-admission faults, expiry faults and same-process service replacement.
  Its complete declared matrix contains 15 cells across 1, 10 and 100 scopes.
* `scripts/native_slo_workspace_poststart.py` retains the separate poststart
  registration diagnostic and its lossless evidence/session helpers. It owns
  two sequential service instances on each of three homes and declares nine
  phase/request offers. See [the poststart contract](../rsp129_workspace_poststart/README.md).

Their module names, evidence encodings, controls and execution claims remain
separate. Same-process service/provider replacement does not establish a
Python-process restart or automatic workspace restoration. Neither diagnostic
grants full installed RSP-128/129 sampling, paired performance or cross-platform
qualification. Existing six-phase workspace scenarios, publisher coalescing,
cache rules and original deadlines are unchanged.
