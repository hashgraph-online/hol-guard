# Kernel peer identity input

The native Unix helper obtains connection UID and group ID from the kernel on
Linux and macOS. Its constructor accepts an actual Unix stream; it has no JSON,
model argument or raw UID constructor. A connected socket is required; Linux
also requires a positive kernel peer PID. Missing or sentinel credentials refuse.
Other platforms have no implementation of this input yet.

This is a connection credential snapshot, not proof of the currently executing
process, a workflow, a tenant role, credential custody or a permitted operation.
Socket descriptors can be transferred. Shared or privileged identities cannot
establish strict separation by presenting a UID. Client authorization must be
verified separately and bound by the future enrollment owner.

The Linux resident client's existing server-PID check shares the same kernel
credential read; its PID comparison, owner check and failure code remain intact.
The existing resident token handshake remains unchanged. This helper neither
adds a worker RPC nor constructs registered-worker admission. The production
business dispatch admission type remains uninhabited. Real cross-identity access,
token isolation, debug access and direct-call bypass tests are still required
before a managed protection claim.

After the resident authenticates a connection, its pending request retains the
kernel UID/group snapshot as private transport metadata. Request JSON cannot
populate or replace it, and response/Cloud projections do not include it. TCP
and unsupported transports retain no Unix identity. Failure to obtain identity
on a supported Unix connection refuses that request. Retaining this input does
not authorize an actor or turn the shared resident token into workflow identity.
