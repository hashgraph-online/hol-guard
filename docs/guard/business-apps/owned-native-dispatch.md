# Private owned native dispatch

The native claimed-review handle retains a lease from the consumed signed
decision, current authenticated snapshot and installed review authority. Before
transport, it checks expiry, clock rollback, unchanged snapshot/authority and
current business floors. It repeats those checks after durable attempt-start
persistence, before invoking the fixed owned Google SDK transport.

The native transition lock remains held through the bounded SDK call and
outcome persistence, so native policy or authority updates cannot race admission.
The handle and credential/input pair are consumed once; no reload or retry
constructor exists. An API acknowledgement is distinct from delivery. Unknown
outcome is retained without automatic retry; failed outcome persistence is
reported separately and never triggers a second send.

The dispatch clock floor comes from the native verifier/release observations,
not a fresh lower wall-clock reading. Policy pushes take the same transition
lock as dispatch and refuse busy instead of replacing the snapshot mid-call.
SDK pre-I/O refusals retain `not_attempted`, distinct from uncertain sends;
simultaneous refusal and journal-write failure has its own bounded error.

The production entry also requires an authenticated registered-worker admission
proof. Its type is currently uninhabited: there is no constructor or valid value,
so the production entry cannot be activated by a native review approval alone.
The future worker owner must establish identity, all intrinsic/organization
floors and credential custody before implementing that proof boundary.

This component publishes no RPC or authenticated worker route. It does not
authenticate workflow/user actors or establish credential isolation. Budget
declarations still refuse through the existing floor until actor/reservation
integration exists. Non-Unix transport, including Windows, refuses before
attempt/transport because journal directory durability is not qualified.
Windows durability, Cloud allocation and live account
journeys remain unfinished. Callback-counter tests qualify native control flow,
not provider behavior, real inference or an installed runtime.
