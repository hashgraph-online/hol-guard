# Guard Cloud Command Capability

## Consent boundary

`hol-guard connect` authorizes read-only Cloud synchronization and signed remote review. It does not, by itself,
authorize Guard Cloud to execute local maintenance or policy commands. Remote command execution is a separate,
device-local capability that must be enabled explicitly after connection and can be revoked without disconnecting
read-only synchronization.

Existing installations are migrated with remote commands disabled. The historical
`GUARD_CLOUD_COMMAND_QUEUE_ENABLED` environment variable remains an emergency disable switch; it cannot create or
widen a command capability.

## Authorization evidence

This repository contains the local queue client and signed review-contract validation, but it does not contain the
Guard Cloud enqueue service or its access-control policy. Consequently, the client does not assume that server-side
workspace membership, roles, or enqueue authorization are sufficient. A leased command must independently satisfy
all local checks below even when its OAuth request is valid.

Server-side release evidence should document, outside this repository, which principals may enqueue each operation,
how workspace and device targeting is enforced, how issuer identity is retained, and how revocation propagates. The
local client remains fail-closed if that evidence is absent or changes.

## Local capability contract

The local command capability is:

- explicitly issued from the local CLI for one connected device and workspace;
- signed by Guard's protected local integrity key;
- limited to an exact set of command operations and an expiration time;
- revocable without clearing OAuth credentials or disabling read-only sync;
- invalid if its signature, device, workspace, version, or expiry is wrong;
- never widened by an environment variable, reconnect, upgrade, or legacy queue state.

Every leased job must declare its operation, schema version, device, workspace, nonce, expiration, idempotency key,
and payload. Guard binds a digest of the complete payload into the job identity. It rejects missing, mismatched,
modified, expired, or replayed bindings before execution and records the decision in the local audit log.

Policy synchronization and approval resolution, plus other state-changing maintenance operations, require a separate
one-job local approval even when the operation is in the device capability. The approval is bound to the complete job
identity and consumed once. Read-only status, update-check, audit, and snapshot operations do not need this second
approval, but still require the device capability. Removal requests do not perform the removal remotely; they return
the existing exact local confirmation command instead of adding a redundant second approval prompt.

## UX and recovery

`hol-guard commands status` and the local dashboard show whether the capability is enabled, its issuer, expiry, exact
operations, pending local approvals, and the revoke command. The recommended enable command selects the read-only
operation set:

```bash
hol-guard commands enable --operations read-only
```

Broader operation sets require explicit operation names. Every state-changing job displays its separate one-job
local-approval command. Revocation takes effect locally immediately while Cloud receipt/evidence synchronization
continues normally:

```bash
hol-guard commands revoke --confirm revoke
```
