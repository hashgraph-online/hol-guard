# Worker-owned account lifecycle

`GoogleSendAccount` retains a worker-verified send credential while preparing
separate immutable command inputs. Each input still requires the existing native
policy, exact review and single-use dispatch path. Preparing several inputs does
not approve them or authorize replay of a previous transaction.

The account owns refresh material. Per-input credentials contain only a private
zeroizing access-token copy, verified identity, original deadlines and a shared
revocation lease. No token getter, serializer, public credential clone, reload
constructor or standalone send method is added.

Revocation or dropping the account invalidates every pending input. This is
local admission revocation, not Google OAuth grant revocation. The fixed send
transport holds a read lease through its bounded HTTP call; revocation
waits for an admitted call and then refuses later calls. An admitted HTTP request
cannot be undone. Network/provider uncertainty still forbids automatic resend.
Poisoned leases are unavailable for preparation, replacement and transport.
Local revoke may recover the poisoned value only to force it to false; it never
restores admission. Transport reports a bounded unavailable/expired error and
does not log credential-bearing panic context.

Replacing authorization requires a fresh worker-verified credential for the
same opaque account, tenant and exact verified primary mailbox. Wrong purpose,
expired authorization and changed identity leave the current account intact.
Successful replacement invalidates all old pending inputs. Fresh inputs bind a
new random account generation into their digest and outbound inspection binding,
so identical bytes cannot reuse an approval from the prior generation. They
require fresh native review. A revoked owner cannot be revived by replacement.

Replacement consumes the existing verified OAuth completion result. The
[registered refresh path](account-refresh.md) now renews authorization against
fixed Google endpoints and invalidates the previous account generation.
It does not implement persistent enrollment, an
authenticated worker registry, disconnect UI or isolated credential custody.
Those remain necessary for the real non-engineer setup/task journey. The
production native worker-admission type still has no valid value. Source tests
qualify lifecycle and transport admission only; no provider account, installed
runtime, live inference or protected business mode is qualified here.
