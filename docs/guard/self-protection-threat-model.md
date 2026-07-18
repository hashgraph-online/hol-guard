# HOL Guard self-protection threat model

Status: accepted for `release/3.1` report-only alpha. Re-run before enforcement GA and after changing identity, observer, or remediation authority.

## Assets and boundaries

Protected assets are the machine runtime, policy, release manifest, service registration, machine identity/generation, signing key, lease continuity state, evidence log, Cloud projection, removal authority, observer credentials, and remediation authority.

Trust boundaries separate the standard user, local administrator/root, Guard machine reporter, operating-system key store, Guard Cloud, vendor adapter, MDM/EDR control plane, workspace administrator, and notification/export consumers. A local administrator and compromised MDM/EDR tenant are strong attackers; controls emphasize detection, independent corroboration, bounded authority, and durable audit rather than claiming absolute prevention.

## Abuse cases and required controls

| Abuse case | Required prevention, detection, and containment |
| --- | --- |
| Complete deletion | Protected native install and service resist standard users; lease expiry alone stays unconfirmed; fresh independent online/absent assertion is required for `unexpectedly_absent`. |
| Partial removal or service disablement | Manifest/package/ACL/service/policy checks emit stable partial/tamper reasons; observer reports `partial`; remediation is allowlisted. |
| Downgrade or executable shadowing | Signed manifest, package identity, minimum version, absolute executable path, and bounded environment fail closed. |
| Device-key theft | Prefer non-exportable hardware keys; bind signatures to workspace/device/installation/generation; revoke keys; lower assurance for fallback storage. |
| Cloned disk or VM snapshot | Installation generation, boot/session identity, monotonic sequence, previous digest, key identity, and Cloud ordering detect rollback/collision. The clone is quarantined pending re-enrollment. |
| Lease replay or stolen payload | Signature, short expiry, strict identity/generation, sequence, previous digest, nonce challenge, idempotency, and rate limits reject replay without extending health. |
| Wall-clock rollback | Compare wall clock with monotonic/boot continuity; reject future/backdated leases and local rollback; never backfill expired proof. |
| Observer spoofing | Separate scoped credentials, signed assertions, rotation/revocation, freshness, vendor tenant binding, and adapter audit; compromise is contained to approved workspace/device scope. |
| Identity collision or ambiguous mapping | Explicit many-source mapping with uniqueness constraints; collisions enter quarantine; no confirmed deletion or automatic remediation follows ambiguous evidence. |
| Malicious remediation request | RBAC, signed expiring job, action allowlist, target generation/version, idempotency, bounded retry/backoff, emergency pause, and immutable audit. No arbitrary command field exists. |
| Compromised adapter | Least-privilege observer/remediation credentials, scope limits, credential health, anomaly alerts, pause/revoke control, and independent Guard evidence prevent silent trust expansion. |
| Cloud outage or proxy failure | Local enforcement remains autonomous; current outbox retries only unexpired evidence; delivery degradation is observable and cannot become healthy or confirmed deletion. |
| Snapshot restore after authorized removal | Single-use authorization and generation binding prevent reuse; observer confirmation and tombstone retain prior lifecycle; reinstall creates a new generation. |
| Workspace crossover | Every credential, claim, mapping, query, mutation, rate-limit key, and audit event is workspace-bound; mismatches reject before projection. |
| Notification or export exfiltration | Redacted canonical fields, RBAC, residency, retention, signed export manifest, bounded webhook payload, and delivery audit. |
| Suppression abuse | Suppression changes routing only, expires automatically, requires actor/reason, preserves underlying state, and is audited. |
| Retirement abuse | Explicit privileged action, audit and reversible re-enrollment; retired devices reject leases and remediation rather than silently disappearing. |

## Security invariants

1. No single local signal can confirm the reporter's complete deletion.
2. Health ingestion and observer ingestion use distinct credentials and cannot execute commands.
3. Silence never becomes authorized removal.
4. A stale or ambiguous observer cannot trigger automatic remediation.
5. Suppression and maintenance never erase evidence.
6. Recovery cannot resolve a managed critical episode without the configured healthy-lease threshold and required fresh observer evidence.
7. User-managed evidence never receives machine-managed assurance.
8. Every authority-changing action is workspace-scoped, authenticated, authorized, rate-limited, expiring where applicable, and audited.

## Verification obligations

Unit and property tests cover schema strictness, state transitions, ordering, replay, expiry, generation monotonicity, and remediation idempotency. Platform tests cover standard-user and administrator tamper on macOS and Windows. Conformance tests cover clock skew, duplicates, mapping collision, partial data, stale observation, and adapter outage. Certified-device tests and an independent red-team exercise remain mandatory before enforcement GA.

