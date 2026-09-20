# RSP129 poststart workspace diagnostic

This separate diagnostic observes poststart workspace registration and a
replacement Guard service using the same private home. At preparation of this
source revision, the combined implementation was unrun; later execution
evidence must identify its exact source. Earlier finite-control results
remain bound to their original source and do not qualify this integration.
The installed diagnostic had not completed at preparation of this revision
and does not grant installed SLO or platform qualification.

The entry point is `scripts/native_slo_workspace_poststart.py`, with required
`--ledger` and `--report` paths. It discovers the installed native runtime
through the existing product API. Its evidence, observation and session
providers use the matching `native_slo_workspace_poststart_*` names. The
incoming [lifecycle sweep](../rsp129_workspace_lifecycle/README.md) keeps its
separate `native_slo_workspace_lifecycle_*` names and evidence contract.

For each declared count, 1, 10 and 100, the fixture owns one fresh private home
and two sequential GuardDaemonServer instances in the same Python process.
The final workspace is the request target; it is a secondary workspace when
the count exceeds one. It retains the installed native identity and requires
default auto mode with the actual native-ready authority.

| Instance | Phase | Required observation |
| --- | --- | --- |
| First | Global readiness | Actual service readiness and authenticated global policy; no registered workspace |
| First | Explicit poststart registration | All declared scopes accepted after readiness, then a last-workspace allow request |
| First | Public policy update | Persisted block policy, matching publisher chain, then a last-workspace block request |
| First | Retirement | Both original native-stop outcomes, one explicit daemon stop and actual owned-state retirement |
| Between instances | Stricter overlay | Exact strict sandbox setting written to the last workspace after verified retirement |
| Second | Global readiness | New publisher/store on the same home; workspace registrations remain empty |
| Second | Explicit registration again | Overlay read back before registration, strict block snapshot acknowledged and last-workspace block request |
| Second | Retirement | The same complete stop and retirement checks, followed by private home cleanup when admitted |

Initial construction and compilation precede observation and are excluded from
timing claims. The original 400 ms readiness/acknowledgment limit, five-second
writer drain and original HTTP/native-stop limits remain unchanged. Publisher
events keep their actual clocks and negative offsets relative to API return.

The fixture uses the supported ReceiptWitness entry result under
contextlib.closing and the real WorkspaceRequestObserver context. It retains
the declared request, complete validated native and committed receipt objects,
publisher events, actual readback joins and writer reports. These are bounded
diagnostic observations; VFS/syscall totals and full persistence coverage remain
unavailable unless independently instrumented.

The private ledger stores admitted objects without removing fields or
truncating values. Full receipt schemas and native-stop diagnostic schemas have
their actual typed validators; other values must be bounded metadata. Logical
packets are checksummed and split across the unchanged 8 KiB PrivateLedger row
limit. Independent file-identity, byte, digest, sequence and complete-object
readback must pass. A partial write, invalid field, overflow or corruption makes
retention incomplete. Later cleanup cannot turn that into a pass. Exceptions
retain the existing bounded qualification failure identity and location; the
external runner must retain the original complete stdout/stderr.

Both returned native-stop diagnostics are copied intact before any later call.
A failed first stop remains a failure even when the final stop succeeds. Actual
quarantine state, publisher/writer/runner state, retained threads and retained
direct processes are observed. No replacement starts unless the first complete
retirement passes. This is not an escaped-descendant census, Python-process
restart, automatic workspace restoration, or a test of loss of metadata hints.

The two finite test modules declare 29 controls: 18 for lossless evidence and
11 for lifecycle/retirement failures. They use synthetic owned state and actual
receipt/private-ledger providers; they do not issue native qualification credit.
Fresh collection and execution must confirm these counts before a real fixture
run. Current source and provider identities, all original command outputs and
process-group retirement belong in that independent harness.

The bounded execution plan is: first collect and run the 29 finite controls;
then, only after source and peer review, run the unchanged ordered 1/10/100
matrix once against the freshly installed current native package. That yields
six offered service instances, nine phase/request offers and three private
homes if all preceding prerequisites pass. Stop on the first failed cell and
retain all offered/terminal/incomplete accounting. Use an external 300-second
process-group bound, retain full stdout/stderr and verify group retirement.
There is no independent ref update or launch in this source packet.

Full sampling, paired baselines, metadata-hint loss, key rotation, expiry and
first-admission faults, Python-process restart and matched platform hardware
remain prerequisites for their respective acceptance claims.
