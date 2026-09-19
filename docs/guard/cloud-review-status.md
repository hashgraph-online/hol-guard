# Reading Cloud Review status

`hol-guard cloud-review status --json` and the local Cloud Review settings page
use the same status projection. Reading status does not enable review, renew
consent, revoke consent, requeue requests, or start workers.

| Field | Meaning |
| --- | --- |
| `connected` | This source has a Cloud sync profile and an OAuth delivery identity. |
| `enabled`, `consent_enabled` | The saved exact-review consent is valid for the current local identity. |
| `expires_at` | The current valid consent expiry, or `null` when unavailable. |
| `delivery_ready` | `true` requires valid consent, no pending recovery failure, and both current workers running. `false` means a required prerequisite is absent. `null` means current worker readiness is unknown. |
| `delivery_readiness_reason` | The missing prerequisite or recovery reason. |
| `last_synced_at` | The last delivery timestamp whose complete identity matches this connection. |
| `delivery_state` | `unknown`: saved attempt state has no current connection binding. A bound historical delivery timestamp does not establish the identity of later attempts. |
| `pending_uploads`, `held_events`, `isolated_events` | Current delivery work, requests awaiting explicit recovery, and quarantined events for this connection. Without a connection binding, delivery and quarantined counts are zero. |
| `activation_error`, `recovery_state` | The saved recovery requirement and current readiness assessment. |

Current daemons observe the decision worker and event upload worker through the
existing authenticated local status route. The observation must match the source
and connection identity and be at most five seconds old. A live daemon by itself
does not prove that both workers are running. Older or unavailable daemons produce
unknown worker readiness while the local connection and consent status remain
available. Historical queue errors and polling timestamps have no proven connection
binding, so `diagnostics.worker` reports those fields as unavailable. Fresh worker
liveness remains in the separate `worker` observation.

The CLI reads an already-running daemon through the existing authenticated identity
check, then requests its status. Each local probe is limited to one second and
64 KB. These requests stay on loopback, ignore proxy settings and refuse redirects.
A missing or slow daemon does not trigger startup or repair during a status read.

An identity change makes old consent ineligible immediately. Status reports that
ineligibility without writing a revocation record; authorization still validates
the binding and retains its existing revocation behavior. Recovery and delivery
timestamps remain tied to their original identities. None of these status fields
establishes policy application or execution permission.

Status uses one read-only SQLite snapshot and validates the existing private
OAuth vault against its saved credential hash. Missing OAuth metadata, legacy
secret envelopes or raw vault keys, missing vault keys and missing installation identity remain
unavailable until an explicit setup or recovery action. Reading status does not
restore metadata, migrate secrets, change file permissions or create identity.
The CLI selects this read path before normal store or policy initialization.
Without an explicit home, it reads only the current Guard storage directory;
status does not discover or migrate an older storage directory.
A missing Guard home, unreadable database or older incomplete schema returns
`status: unavailable` and unknown delivery readiness without creating or repairing
storage. Run an explicit setup or repair action when recovery is needed.

Consent signature checks retain the configured integrity backend. An unexpired
signer cache must match the snapshot's integrity marker. A local or fallback
backend may read its existing private key without promotion; an OS-only backend
uses its existing protected read method and never substitutes a local key. If
that signer is unavailable, status reports the verification reason and cannot
claim valid consent. Normal authorization and recovery retain their existing
signer and revocation behavior.
