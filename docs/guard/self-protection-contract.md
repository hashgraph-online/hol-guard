# HOL Guard self-protection contract

Status: frozen for the `release/3.1` report-only alpha. Enforcement remains gated by certified endpoint and adapter evidence.

## Product guarantee

For a certified machine-managed installation, Guard prevents standard users from modifying the protected runtime, policy, identity, service registration, evidence, and removal surfaces. Guard reports signed local evidence on a machine cadence. Guard Cloud correlates that evidence with an independently authenticated MDM or EDR observer before describing complete deletion as confirmed.

Administrators and compromised platform authorities remain able to remove or subvert software. A local reporter cannot prove its own continued existence after deletion. Therefore:

- a missed lease without fresh independent observation is `unknown`, `late`, `offline`, or `suspected_absent`, never confirmed deletion;
- user-managed protection is explicitly `user-managed` and best-effort;
- machine management without certified native/key controls is `mdm-managed-unverified`;
- only a certified package, protected machine state, and supported key store qualify as `mdm-managed`;
- automatic remediation is external, bounded, independently authorized, and disabled for ambiguous or stale targets.

## Frozen v1 schemas

The normative JSON Schemas are:

- [`local-integrity-snapshot.v1`](schemas/local-integrity-snapshot-v1.schema.json)
- [`protection-lease.v1`](schemas/protection-lease.v1.schema.json)
- [`observer-assertion.v1`](schemas/observer-assertion.v1.schema.json)
- [`protection-state.v1`](schemas/protection-state.v1.schema.json)
- [`removal-authorization.v1`](schemas/removal-authorization.v1.schema.json)
- [`remediation-job.v1`](schemas/remediation-job.v1.schema.json)

Unknown fields are rejected. Identifiers are workspace-scoped. Timestamps are UTC RFC 3339. Durations and payload sizes are bounded. Contracts contain identifiers, hashes, state, and reason codes—not usernames, home paths, command content, access tokens, private keys, or raw vendor payloads.

Every `signature` covers the UTF-8 RFC 8785 canonical JSON bytes of the complete object with the top-level `signature` member omitted. The `value` is canonical padded base64. Ed25519 signatures are 64 bytes. ECDSA P-256 SHA-256 signatures use the fixed-width 64-byte IEEE P1363 `r || s` encoding and require low-S form. Verifiers reject non-canonical encodings, unknown or revoked key identifiers, algorithm/key mismatches, and signatures over any other serialization.

## State and reason stability

Protection states are `healthy`, `degraded`, `late`, `offline`, `unknown`, `suspected_absent`, `tampered`, `unexpectedly_absent`, `removal_pending`, `removed_authorized`, `repairing`, `recovered`, and `retired`.

Evidence detection states are `present`, `absent`, `partial`, `unknown`, and `unsupported`. `absent` means complete absence on the observer's declared scope. `partial` means some required surface is missing, modified, disabled, downgraded, shadowed, or unhealthy. Neither state is inferred from lease silence.

Stable reason codes are grouped by authority:

- lease: `lease_current`, `lease_expired_in_grace`, `lease_expired`, `lease_replayed`, `lease_out_of_order`, `lease_wrong_generation`, `lease_wrong_identity`, `lease_invalid_signature`, `lease_future_dated`, `lease_oversized`;
- observer: `observer_current_present`, `observer_current_absent`, `observer_current_partial`, `observer_offline`, `observer_stale`, `observer_mapping_ambiguous`, `observer_credential_invalid`;
- local integrity projection: `local_integrity_degraded` and `local_integrity_tampered`; the source snapshot retains its frozen component-specific reason code for manifest, package, ACL, service, policy, key, shadowing, downgrade, or continuity failure;
- lifecycle: `removal_authorized`, `removal_authorization_expired`, `removal_completed_confirmed`, `repair_requested`, `repair_in_progress`, `recovery_threshold_met`, `device_retired`;
- policy: `maintenance_window_active`, `suppression_active`, `observer_required`, `legacy_unattested`.

New reason codes require a schema revision. Consumers must render unknown future codes as unsupported evidence, never as healthy.

## Deterministic transition precedence

Inputs are evaluated in this order. The first matching row wins.

| Priority | Condition | State |
| --- | --- | --- |
| 1 | Device explicitly retired | `retired` |
| 2 | Fresh observer confirms absence under a valid removal authorization | `removed_authorized` |
| 3 | Valid removal authorization is active and removal is not yet confirmed | `removal_pending` |
| 4 | Remediation adapter accepted an eligible bounded job | `repairing` |
| 5 | Fresh observer reports online and complete absence without valid removal | `unexpectedly_absent` |
| 6 | Current local or observer evidence reports modification/partial health | `tampered` or `degraded` according to the frozen severity mapping |
| 7 | Recovery threshold is met after an incident | `recovered` for one transition, then `healthy` |
| 8 | Current healthy lease and required fresh healthy observer exist | `healthy` |
| 9 | Approved maintenance window or fresh observer reports endpoint offline | `offline` |
| 10 | Lease expired but remains inside grace | `late` |
| 11 | Managed lease silence exceeds the suspicion threshold without fresh observer evidence | `suspected_absent` |
| 12 | No authoritative current evidence | `unknown` |

Suppressions affect notification routing only. Maintenance windows affect expected connectivity but preserve raw state and evidence. Clock rollback, snapshot restore, generation rollback, and replay reject the input and cannot extend health. Repair never erases the prior episode. Recovery requires the configured consecutive healthy leases and, when required, a fresh independent present assertion.

## Server-enforced bounds

Workspace policy may tighten, but not exceed, these bounds:

| Control | Minimum | Default | Maximum |
| --- | ---: | ---: | ---: |
| Machine lease cadence | 60 s | 300 s | 900 s |
| Lease lifetime | 180 s | 900 s | 1,800 s |
| Grace after expiry | 0 s | 600 s | 3,600 s |
| Suspected-absence threshold | 900 s | 3,600 s | 86,400 s |
| Observer freshness | 60 s | 600 s | 3,600 s |
| Challenge lifetime | 30 s | 120 s | 300 s |
| Suppression | 60 s | 3,600 s | 86,400 s |
| Maintenance window | 60 s | 3,600 s | 604,800 s |
| Removal authorization | 30 s | 120 s | 300 s |
| Remediation job | 60 s | 900 s | 3,600 s |

The lease lifetime must be at least twice the cadence and no more than six times the cadence. Grace does not extend cryptographic lease validity. Suppressions and maintenance windows require an authorized actor, bounded reason, start, expiry, and immutable audit record.

Signed lease, challenge, removal-authorization, and remediation-job contracts encode expiry as `issuedAt` plus a schema-bounded `validForSeconds`. Consumers derive the exclusive expiry instant from those fields and reject evidence at or after that instant. These contracts intentionally do not carry a second absolute expiry timestamp: JSON Schema 2020-12 cannot enforce arithmetic consistency between two timestamps, which would let schema-only consumers accept an overlong lifetime. Observer assertions retain `expiresAt` because their freshness is projected and bounded by Guard Cloud rather than authorizing a local action.

## Key assurance

macOS prefers a non-exportable Secure Enclave or system Keychain key whose ACL is machine-owned and prompt-free in scheduled context. Windows prefers a non-exportable TPM-backed CNG key scoped to the machine. `hardware-backed` is required for the highest managed assurance. `os-protected` is permitted in report-only mode when hardware storage is unavailable. `file-backed` is lower assurance, must be policy-visible, and cannot qualify for enforcement GA. `unavailable` and `unknown` cannot emit healthy managed evidence.

Rotation creates a new key identifier without changing the installation generation. Revocation prevents new leases immediately. Loss, rollback, or untrusted replacement of key state creates a new installation generation and requires re-enrollment.

## Privacy, retention, and residency

Cloud stores the minimum evidence needed to reconstruct state: workspace/device/installation/generation identifiers; schema and key identifiers; timestamps and sequence; state/reason codes (including concurrent active causes); version and assurance; evidence digests; observer mapping identifiers; authorization/remediation audit metadata; and delivery outcomes.

Raw snapshots and vendor payloads are rejected or reduced to the schema before persistence. Private keys, refresh/access tokens, usernames, home paths, IP addresses, command content, and unrestricted host metadata are forbidden. Display labels are stored separately from evidence and are not signed claims.

Default retention is 30 days for raw accepted/rejected ingestion evidence, 400 days for transitions/incidents/audit events, and the workspace-configured legal minimum for bounded tombstones. Workspace deletion schedules removal after any active legal hold. Legal hold records actor, reason, scope, start, and release. Tenant export contains canonical records, digests, schema versions, and a signed manifest. Data remains in the workspace's selected residency region; adapters normalize in-region or transmit only the frozen assertion.

## Authority and ownership

- The Guard device key signs local snapshots/leases only; it cannot authorize removal or remediation.
- Observer credentials assert vendor-neutral observation only; they cannot impersonate a Guard device or mutate workspace policy.
- Workspace administrators authorize removal, maintenance, suppression, retirement, and remediation policy according to RBAC.
- Adapters execute only a signed, expiring `remediation-job.v1` allowlist action.
- Guard Cloud owns ordering, projection, incident deduplication, and audit retention. It cannot weaken local policy through the health channel.
