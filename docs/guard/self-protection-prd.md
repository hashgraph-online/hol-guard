# HOL Guard self-protection and deletion detection PRD

## Document control

- **Status:** Proposed
- **Priority:** P0 enterprise readiness
- **Owners:** Guard runtime, Guard Cloud, release engineering, and endpoint management
- **Platforms:** macOS and Windows first; Linux contracts must remain portable
- **Delivery line:** `release/3.1`, published as PEP 440 alpha releases on PyPI
- **Release dependency:** The repository's 3.1 release automation owns build and publication; this work consumes and verifies that contract but does not implement it.
- **Implementation tracker:** [Self-protection TODO](./self-protection-todo.md)
- **Related work:** [MDM managed-install ADR](./adr/0001-mdm-managed-install-contract.md), [MDM GA roadmap](./mdm-general-availability-roadmap.md), [MDM deployment](./mdm-deployment.md)
- **Last updated:** July 17, 2026

## Summary

HOL Guard must remain honest when its own enforcement surface is damaged or removed. A user-managed installation cannot reliably prevent deletion by the same user, and no process can report after its complete removal. An MDM-managed installation can resist standard-user modification with root/SYSTEM ownership and platform ACLs, but a privileged actor can still remove it.

This PRD defines a layered local and Cloud contract that:

1. makes MDM-managed Guard difficult for standard users and user-level agents to modify or remove;
2. detects missing, modified, shadowed, downgraded, disabled, or partially removed protection;
3. gives Guard Cloud a signed health lease for each enrolled installation;
4. correlates that lease with an independent MDM/EDR observation;
5. opens an incident when Guard disappears without an authorized removal workflow; and
6. triggers repair through an external control plane that remains available when Guard does not.

The enterprise guarantee is deliberately bounded:

> Standard users and user-level agents cannot remove an MDM-managed Guard installation. Privileged removal is detectable, auditable, and automatically remediated by an independent MDM or EDR control plane.

## Problem

Today, several useful primitives exist, but they do not form a complete deletion-defense contract:

- `guard/mdm/manifest.py` verifies release-manifest signatures, per-file hashes, ownership, and writable permissions.
- `guard/mdm/lifecycle.py` reports machine and user health, detects command shadowing, and requires authorization for managed deactivation.
- Guard Cloud already records devices, last-seen activity, runtime sessions, receipts, and policy acknowledgements.
- Existing Cloud device freshness is activity-derived. It does not prove that a machine runtime is installed and healthy, does not distinguish an offline endpoint from deleted Guard, and is not independently corroborated.
- The local runtime cannot emit evidence after its executable, state, hooks, daemon, and launch registrations are removed.

As a result, ordinary sync staleness can hide materially different conditions: a laptop is asleep, network egress is blocked, Guard is stopped, Guard is partially tampered with, Guard was legitimately removed, or Guard was deleted by a privileged actor.

## Goals

- Define explicit self-protection promises for user-managed and MDM-managed installations.
- Protect machine-owned runtime, policy, lifecycle, logs, service registration, and device identity from standard-user modification.
- Continuously attest runtime integrity, policy integrity, harness coverage, and service supervision.
- Send replay-resistant, device-bound health leases to Guard Cloud on a predictable schedule independent of receipts or agent activity.
- Add an independent MDM/EDR observation channel that does not use local Guard credentials.
- Detect and classify unexpected disappearance within a configurable, bounded interval.
- Preserve an immutable Cloud timeline for tamper signals, authorized removal, absence, repair attempts, and recovery.
- Automatically request reinstall or repair through MDM/EDR rather than through the missing Guard runtime.
- Avoid false critical incidents for expected shutdown, travel/offline windows, device retirement, and authorized uninstall.
- Keep local enforcement functional when Guard Cloud is unavailable.

## Non-goals

- Preventing a determined root, local administrator, firmware, hypervisor, or physical-console actor from removing software.
- Treating interception of shell deletion commands as a security boundary.
- Building an MDM or EDR product inside Guard Cloud.
- Requiring kernel extensions, system extensions, packet filters, or broad Full Disk Access for the first release.
- Claiming deletion merely because a user-managed laptop has not synced.
- Remotely executing arbitrary commands through the health channel.
- Uploading command text, prompts, secrets, file contents, usernames, or unrestricted host inventory.
- Changing the stable 2.x channel or making stable installations consume prereleases.

## Personas

- **Endpoint administrator:** deploys Guard, configures detection/remediation, and retires devices.
- **Security administrator:** defines absence thresholds, receives incidents, and audits removal.
- **Developer:** cannot accidentally or programmatically weaken an MDM-managed installation from user context.
- **Incident responder:** can distinguish offline, tampered, deleted, authorized removal, and recovered states.
- **Guard Cloud operator:** can monitor lease processing, observer coverage, alert delivery, and remediation outcomes.

## Threat model

### In scope

- A user-level agent deletes user hooks, shims, user-scoped Guard state, or a user-managed executable.
- A standard user attempts to modify or remove an MDM-managed runtime or policy.
- A privileged actor kills services, removes launch registrations, deletes files, downgrades Guard, blocks egress, or removes only selected protection surfaces.
- An attacker shadows `hol-guard` earlier in `PATH` while the machine package remains installed.
- A cloned endpoint replays a previously valid heartbeat.
- Local time is rolled back or state is restored from a snapshot.
- Guard is legitimately deactivated, uninstalled, migrated, or the endpoint is retired.
- Guard Cloud, the endpoint, or the MDM integration is temporarily offline.

### Trust boundaries

- **Local Guard reporter:** strong evidence while its protected key and runtime remain trustworthy; incapable of proving its own continued existence after deletion.
- **Machine supervisor:** root/SYSTEM-owned scheduled health runner or service registration; stronger than user context but removable by administrators.
- **MDM/EDR observer:** independent device-context detection and remediation authority with separate credentials.
- **Guard Cloud:** durable lease state, correlation, incident routing, authorization, and audit evidence.
- **Human administrator:** authorizes removal, suppression windows, device retirement, and remediation policy.

## Deployment-mode guarantees

### User-managed installation

- Guard SHOULD intercept clearly destructive commands when its hooks are active, but documentation and UI MUST label this best-effort.
- Guard MUST detect missing hooks, shims, daemon registration, executable shadowing, local state loss, and version drift when any Guard entry point still runs.
- Connected installations SHOULD send health leases while running.
- A missed lease alone MUST remain `unknown` or `offline` unless an independent observer confirms the endpoint is online and Guard is absent.
- Cloud SHOULD notify the owner of prolonged unexpected silence, but MUST not claim tamper certainty without corroboration.
- Reconnection after local state deletion MUST create a new installation generation and MUST NOT silently inherit the old device's trust or removal state.

### MDM-managed installation

- Runtime, manifest, managed policy, service registration, machine identity, and machine logs MUST be root/SYSTEM owned and non-writable by standard users.
- The native package and signed release manifest MUST remain the installation authority.
- Platform ACLs MUST deny standard-user update, removal, replacement, ownership change, and service-registration changes.
- A machine-context health runner MUST execute independently of user harness activity.
- MDM/EDR detection MUST independently report package presence and repair unhealthy or absent installations.
- Managed policy MUST prevent local weakening and require short-lived authorization for supported deactivation or uninstall.
- Unexpected absence confirmed by MDM/EDR MUST create a high- or critical-severity Cloud incident and remediation request.

## Target architecture

```text
Guard runtime and machine supervisor
  -> verify manifest, native package, ACLs, policy, service, hooks, and version
  -> sign health lease with non-exportable device key
  -> Guard Cloud health ingest

MDM / EDR control plane (independent credentials)
  -> run vendor-neutral Guard detection command or native package query
  -> report observer assertion to Guard Cloud
  -> reinstall or repair from signed release channel when policy requires

Guard Cloud
  -> validate identity, signature, sequence, generation, freshness, and workspace
  -> correlate local lease + observer assertion + authorized-removal intent
  -> derive device protection state
  -> open/update/resolve incident and emit SIEM/webhook evidence
```

## Requirements

### SP-R001: Protected machine installation

- Use the machine paths and ownership contract in ADR 0001.
- Verify the release manifest before every machine lifecycle operation and on the scheduled health cadence.
- Validate native package identity, platform signature/notarization, owner, ACL/mode, service registration, expected executable path, and minimum allowed version.
- Detect complete absence separately from partial tamper.
- Treat a user-writable runtime, manifest, policy, key, service definition, or machine log directory as tampered.
- Store the device signing key in Keychain/TPM-backed platform storage when available. A file-backed fallback MUST be explicitly reported and policy-controllable.
- Protect health-runner configuration from standard-user disablement. The runner MUST use an absolute machine-owned executable path and a bounded environment, not `PATH` lookup.
- Preserve enough machine audit data across repair to link the pre-repair and post-repair installation generations.

### SP-R002: Local integrity snapshot

The local snapshot MUST use a versioned schema and include only bounded, non-secret fields:

- workspace, device, machine installation, and installation-generation identifiers;
- product version, build ID, source commit, package identity, manifest hash, and policy hash;
- platform, architecture, install owner, and key-protection level;
- manifest, native package, owner/ACL, service, daemon, command-shadowing, update, and policy states;
- required harness count and aggregate protected/degraded/missing counts without home paths or usernames;
- stable reason codes and remediation class;
- local wall-clock time, monotonic uptime sample, sequence number, previous lease digest, and boot/session identifier.

Snapshot generation MUST be read-only, bounded, prompt-free, and safe when state is partially missing. It MUST NOT trust environment overrides for machine paths.

### SP-R003: Signed Cloud health lease

- Add a dedicated health endpoint and schema; do not infer health from receipts or ordinary event sync.
- Each lease MUST be signed by the enrolled device key and bound to workspace, device, machine installation, installation generation, schema version, sequence, nonce/challenge when requested, issue time, expiry, and snapshot digest.
- Cloud MUST reject wrong-workspace, wrong-device, expired, future-dated, duplicate, out-of-order, rollback-generation, invalid-signature, and oversized leases.
- A successful lease extends protection only until `leaseExpiresAt`; it never proves future health.
- Default MDM cadence SHOULD be 5 minutes with a 15-minute lease. Defaults MUST be workspace-configurable within server-enforced safe bounds.
- The local outbox MAY retry a current lease, but MUST NOT backfill stale leases as proof of continuous health.
- Lease delivery failure MUST not weaken local enforcement.

### SP-R004: Independent observer assertion

- Define a vendor-neutral observer API and signed assertion schema for MDM/EDR adapters.
- Observer credentials MUST be distinct from Guard device credentials and scoped to one organization/workspace and approved device identifiers.
- Assertions MUST identify the observer, observed device, observation time, package presence, detected version, detection state, and remediation state.
- Guard Cloud MUST support push assertions from adapters and an adapter polling model without embedding vendor logic in Guard core.
- MDM device identity mapping MUST be explicit and auditable. Ambiguous mappings MUST not automatically remediate.
- An observer assertion that the endpoint is online while Guard is absent or unhealthy is stronger evidence than a missed local lease.
- Observer integrations MUST expose freshness, last success, last error, and credential-rotation health.

### SP-R005: Cloud protection state machine

Cloud MUST derive state from leases, observer assertions, removal intent, device lifecycle, and suppression windows. Required states:

| State | Meaning |
| --- | --- |
| `healthy` | Current valid lease; local snapshot healthy; observer healthy or not required by policy |
| `degraded` | Current lease reports a repairable protection gap |
| `late` | Lease expired inside the workspace grace window |
| `offline` | Endpoint is independently reported offline or in an approved maintenance window |
| `unknown` | Guard is silent and no fresh independent observation exists |
| `suspected_absent` | A managed installation remains silent beyond the extended threshold and is not confirmed offline; deletion is possible but unproven |
| `tampered` | Valid local or observer evidence reports modification, shadowing, downgrade, or disablement |
| `unexpectedly_absent` | Observer confirms endpoint online and Guard absent without valid removal intent |
| `removal_pending` | Authorized, unexpired removal workflow is active |
| `removed_authorized` | Observer confirms removal under a valid workflow |
| `repairing` | Independent control plane accepted remediation |
| `recovered` | New/current generation meets recovery criteria after an incident |
| `retired` | Administrator retired the endpoint; leases and remediation are no longer expected |

State transitions MUST be deterministic, idempotent, workspace-scoped, and recorded with their input evidence. A scheduled Cloud evaluator MUST detect lease expiry; ingestion alone is insufficient.

### SP-R006: Authorized removal and retirement

- Cloud or MDM authority MUST issue a short-lived, single-use removal authorization bound to workspace, device, installation generation, operation, actor, reason, and expiry.
- Local uninstall/deactivation MUST record `removal.started` before mutation when reachable and `removal.completed` after successful cleanup. These are helpful evidence, not proof when missing.
- The independent observer MUST confirm package absence before Cloud marks `removed_authorized`.
- Silence without a valid authorization MUST never become authorized removal.
- Reinstall after authorized or unexpected removal MUST create a new generation while retaining the stable device relationship and incident history.
- Device retirement MUST be an explicit Cloud/MDM action and MUST be reversible only through a new enrollment workflow.

### SP-R007: Incident and notification behavior

- Open or update one deduplicated incident per device and active absence/tamper episode.
- Open a missed-lease incident for `suspected_absent` even without observer corroboration, while clearly labeling deletion unconfirmed.
- Suggested severity: `degraded` medium, `suspected_absent` high for managed installations, confirmed tamper high, and confirmed unexpected absence critical. Workspace policy MAY raise but not lower the managed minimum.
- Include last healthy lease, last observer assertion, last policy/version, first missed deadline, removal authorization status, remediation attempts, and recovery evidence.
- Never include raw commands, prompts, secrets, usernames, home paths, or unrestricted host inventory.
- Emit redacted events for `protection.degraded`, `protection.tampered`, `protection.lease_missed`, `protection.unexpectedly_absent`, `protection.remediation_started`, `protection.recovered`, and authorized removal lifecycle.
- Route through existing Guard Cloud incident, webhook, notification, and SIEM mechanisms with retry and delivery evidence.
- Alert suppression MUST require an actor, reason, bounded expiry, and audit record. Suppression MUST not rewrite health state.

### SP-R008: Independent remediation

- Cloud MUST request remediation only through an approved MDM/EDR adapter or administrator workflow; the health endpoint cannot execute commands.
- Remediation actions MUST be limited to signed install, repair, policy refresh, service re-registration, and approved version convergence.
- Every request needs an idempotency key, target generation, desired version/channel, reason, expiry, and actor/policy source.
- Adapters MUST report accepted, running, succeeded, failed, unsupported, and timed-out states.
- Repeated failures MUST use bounded exponential backoff and escalate rather than loop indefinitely.
- Recovery requires both a valid healthy lease and, when configured, a fresh healthy observer assertion. Require at least two consecutive healthy lease intervals before automatically resolving a critical absence incident.

### SP-R009: Offline, outage, and false-positive controls

- MDM-reported device offline state, approved maintenance windows, and explicit travel/offline policy MAY defer absence incidents.
- Guard Cloud outage time MUST not count against endpoint lease compliance until ingestion recovers and the server grace policy is applied.
- Server receive time is authoritative for lease freshness; local timestamps are evidence only.
- A blocked Guard Cloud endpoint while MDM reports the device online and Guard installed SHOULD be `unknown` or `degraded`, not `unexpectedly_absent`.
- Workspace policy MUST define observer-required mode, lease interval, grace, maintenance windows, and escalation routing within safe server limits.

### SP-R010: Evidence, retention, and privacy

- Retain append-only transition evidence separately from the mutable current-state projection.
- Record evidence digests and source identities so incident timelines can be independently reconciled.
- Define tenant-configurable retention with a minimum security-audit floor for enterprise plans.
- Provide workspace and device export APIs using the enterprise event taxonomy and integrity manifests.
- Device signing keys and observer credentials MUST never appear in diagnostics, exports, URLs, logs, or UI.
- Hostnames and network addresses remain optional and separately governed; health correlation MUST work with opaque device identifiers.

### SP-R011: User-managed connected-device behavior

- Connected user-managed installations MAY opt into signed leases using a user-scoped key and MUST be labeled `assuranceLevel=user-managed`.
- Cloud MUST not represent user-managed silence as suspected or confirmed deletion without an independent observer; prolonged silence remains `unknown` with an owner notification.
- The UI MUST explain the difference between `unknown`, `unexpectedly_absent`, and `removed_authorized`.
- A user may disconnect or uninstall their own user-managed installation. Cloud retains an audit tombstone according to policy rather than silently deleting device history.

### SP-R012: Compatibility and rollout

- Version local snapshot, lease, observer assertion, state projection, event, and removal-authorization schemas independently.
- Old clients remain visible as `legacy_unattested`; they are not silently treated as healthy.
- Roll out in report-only mode before incident and remediation enforcement.
- Workspace policy must support staged rings, per-device exemptions with expiry, and an emergency server-side pause for remediation requests.
- Health ingestion and state evaluation must be horizontally scalable, replay-safe, rate-limited, and observable.

### SP-R013: Release-branch integration and PyPI alpha evidence

- The 3.1 release train owns branch protection, version selection, TestPyPI/PyPI publication, provenance, prerelease creation, and stable-channel isolation. Self-protection changes consume that release service as an external delivery dependency.
- Self-protection implementation PRs for the 3.1 release line MUST branch from and target `release/3.1`, not `main`.
- Every PR MUST complete the repository's review loop against its release-branch head: local verification, TestPyPI canary when available, all required checks, thread-level bot review, and a quiet window after the final push.
- A self-protection PR MUST NOT add or modify release automation unless release-infrastructure work is separately requested and reviewed. Release failures are handed to the release owner rather than repaired inside an unrelated feature or documentation PR.
- Merges into `release/3.1` MUST be eligible to produce a unique, monotonically increasing PEP 440 prerelease in the `3.1.0aN` series.
- Alpha publication MUST use PyPI trusted publishing, retain build provenance, and create a matching GitHub prerelease/tag such as `alpha/v3.1.0aN` targeting the published source commit.
- The workflow MUST reject publication from any other branch, a dirty or mismatched source ref, a reused version, a non-alpha version, or an alpha outside the branch's declared `3.1` line.
- Pull requests SHOULD publish a uniquely versioned TestPyPI canary. The post-merge PyPI alpha MUST be built again from the merged `release/3.1` commit rather than promoting an untrusted PR artifact.
- Alpha publication MUST keep package variants explicit. If only `hol-guard` is approved for alpha, the workflow MUST exclude `plugin-scanner` rather than accidentally publishing it.
- Stable `hol-guard update` and unconstrained installation MUST continue to ignore prereleases. Alpha validation MUST install the exact published version, for example `uv tool install --force 'hol-guard==3.1.0aN'`.
- The release workflow MUST smoke-test the exact PyPI artifact on the supported alpha Python matrix and verify `hol-guard --version` reports the published version.
- A failed alpha publication, install, or smoke test blocks completion of the PR review loop. The repair MUST use a new commit and new alpha serial; published versions are immutable and never overwritten.
- Promotion from `release/3.1` to a stable line requires a separate, explicit release decision. Alpha merges MUST NOT update stable tags, stable GitHub release markers, stable containers, or stable updater metadata.
- Completion evidence for each self-protection merge MUST record the merged source SHA, published alpha version, PyPI project URL, provenance or prerelease URL, exact-version install result, and stable-channel isolation result.

## Cloud data model

Minimum logical records:

- `guard_device_installations`: stable device relationship plus current installation generation and assurance level;
- `guard_protection_leases`: append-only validated lease headers and snapshot digests;
- `guard_observer_assertions`: append-only MDM/EDR observations;
- `guard_protection_state`: current derived state, deadlines, evidence references, and policy version;
- `guard_removal_authorizations`: single-use removal/retirement workflow;
- `guard_remediation_jobs`: external adapter request and outcome;
- `guard_protection_transitions`: append-only transition/audit timeline.

Raw signatures may be retained only as required for verification/audit policy. Current-state rows MUST be reconstructable from append-only evidence.

## API surface

Names are provisional; semantics are required:

- `POST /api/guard/protection/leases`
- `POST /api/guard/protection/observer-assertions`
- `GET /api/guard/protection/devices/{deviceId}`
- `POST /api/guard/protection/devices/{deviceId}/removal-authorizations`
- `POST /api/guard/protection/devices/{deviceId}/maintenance-windows`
- `POST /api/guard/protection/remediation-jobs`
- `GET /api/guard/protection/incidents/{incidentId}/evidence`

All mutation APIs require explicit workspace authorization, bounded schemas, idempotency, audit actor, and rate limits. Device and observer ingestion use separate authentication paths.

## Success metrics and service objectives

- 99.9% of valid health leases accepted and projected within 60 seconds.
- 99% of MDM-confirmed unexpected absence incidents created within 5 minutes of the fresh observer assertion.
- 99% of accepted remediation requests delivered to the adapter within 5 minutes.
- Fewer than 0.1% of enrolled MDM devices produce a false confirmed-absence incident per 30 days during pilot.
- 100% of authorized removals have actor, reason, generation, expiry, and independent confirmation evidence.
- 100% of critical incident auto-resolutions meet the configured consecutive-healthy recovery rule.
- 100% of merged `release/3.1` alpha release candidates produce one traceable PyPI `3.1.0aN` artifact or a visible blocking failure; no merge is silently treated as shipped.
- 100% of published alphas map to one immutable release-branch commit, provenance record, and GitHub prerelease.

## Acceptance criteria

1. A standard user cannot alter or delete machine-owned Guard files, policy, service registration, or key material on certified macOS and Windows images.
2. Deleting or modifying each protected surface produces a stable local reason code when the health runner remains available.
3. Removing the entire managed runtime causes Cloud to move from `late` to `suspected_absent` after the extended threshold and to `unexpectedly_absent` after an independent online/absent assertion.
4. An offline endpoint does not produce a confirmed-deletion incident.
5. Replayed, cloned, future-dated, expired, out-of-order, or wrong-generation leases are rejected.
6. Authorized uninstall reaches `removed_authorized`; the same deletion without authorization opens a critical incident.
7. MDM remediation reinstalls Guard and Cloud resolves only after the recovery criteria pass.
8. User-managed silence is clearly labeled unknown unless corroborated.
9. Every transition and remediation attempt appears in redacted incident and export evidence.
10. A real-device certification matrix passes across install, tamper, deletion, offline, authorized removal, repair, upgrade, downgrade, snapshot restore, and device retirement scenarios.
11. The final review-loop merge targets `release/3.1`; the release service publishes a new `3.1.0aN` artifact from that merged SHA; and the self-protection completion record proves exact-version installation without changing the stable channel.

## Release gates

- Signed production installers and protected machine paths are GA-certified.
- Cloud schemas, state machine, scheduled expiry evaluator, and migrations pass replay and concurrency tests.
- At least one Apple MDM and one Windows MDM adapter pass observer and remediation conformance.
- Incident, webhook/SIEM, retention, RBAC, and deletion workflows pass security review.
- Red-team tests cover local deletion, service disablement, key theft attempts, lease replay, observer spoofing, identity collision, and remediation abuse.
- Pilot evidence demonstrates the success metrics before enforcement defaults on.
- The separately owned `release/3.1` release service enforces branch/version coupling, trusted publishing, immutable alpha serials, prerelease isolation, and exact-artifact smoke tests before self-protection work can claim completion.

## Open decisions

- Hardware-backed key requirements and supported fallback by platform/edition.
- Initial MDM/EDR adapters and whether Cloud receives push assertions or polls vendor APIs.
- Default lease/grace intervals for workstation, CI, and always-on server profiles.
- Minimum audit retention and customer-configurable upper bounds.
- Whether confirmed unexpected absence should automatically isolate Cloud command capabilities for the device.
