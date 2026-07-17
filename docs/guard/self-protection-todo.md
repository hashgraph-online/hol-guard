# HOL Guard self-protection implementation TODO

This tracker implements the [self-protection and deletion detection PRD](./self-protection-prd.md). Tasks are ordered by dependency. Checked boxes require merged code, tests, operational evidence, and documentation; prototype-only behavior does not count.

## P0: 3.1 release-line integration

Release automation is a separately owned dependency. These items verify and consume that service; they do not authorize self-protection PRs to edit workflow or publication infrastructure.

- [ ] **SP-T087:** Confirm `release/3.1` is protected and record it as the base and merge target for every 3.1 self-protection PR.
- [ ] **SP-T088:** Confirm the release owner has enabled a branch-bound 3.1 alpha service before the first implementation merge; link its contract and responsible owner from the implementation epic.
- [ ] **SP-T089:** Before each PR, update the feature worktree from the current `release/3.1` head and verify the diff contains only the scoped self-protection change.
- [ ] **SP-T090:** Complete the repository review loop against `release/3.1`: focused local verification, required checks, TestPyPI canary when provided by the release service, thread-level bot review, and the final quiet window.
- [ ] **SP-T091:** After merge, wait for the separately owned release service to publish a new, unique PEP 440 `3.1.0aN` `hol-guard` artifact built from the merged release-branch SHA.
- [ ] **SP-T092:** Verify the published alpha maps to the merged SHA and has matching provenance, checksums, SBOM, and GitHub prerelease evidence.
- [ ] **SP-T093:** Install the exact PyPI alpha in a clean environment and assert the CLI version, import health, and the self-protection behavior changed by the PR.
- [ ] **SP-T094:** Verify stable `hol-guard update`, unconstrained installs, stable tags, stable containers, and stable updater metadata remain isolated from the alpha.
- [ ] **SP-T095:** Record the PR, merge SHA, PyPI version and URL, prerelease/provenance URL, exact install command, smoke result, and stable-isolation result in the completion evidence.
- [ ] **SP-T096:** If publication or smoke verification fails, leave the self-protection item incomplete and hand the failure to the release owner; do not patch release automation inside the feature PR.
- [ ] **SP-T097:** Keep the PR review runbook explicit that completion means merge into `release/3.1` plus verified PyPI alpha evidence, not merely a green PR or merged commit.
- [ ] **SP-T098:** Define forward-port, backport, stabilization, and promotion rules between `release/3.1`, future release branches, and `main` without carrying alpha-only metadata into stable channels.

## P0: contracts and threat model

- [ ] **SP-T001:** Approve the bounded enterprise guarantee and user-managed assurance language.
- [ ] **SP-T002:** Freeze `local-integrity-snapshot.v1`, `protection-lease.v1`, `observer-assertion.v1`, `protection-state.v1`, `removal-authorization.v1`, and `remediation-job.v1` schemas.
- [ ] **SP-T003:** Freeze stable state and reason-code enums, including `unknown`, `suspected_absent`, confirmed complete absence, and partial tamper.
- [ ] **SP-T004:** Specify the deterministic state-transition table for lease expiry, observer freshness, maintenance windows, removal, repair, recovery, and retirement.
- [ ] **SP-T005:** Define server-enforced minimum/maximum lease interval, expiry, grace, suppression, and maintenance-window bounds.
- [ ] **SP-T006:** Complete abuse cases for deletion, partial removal, service disablement, downgrade, shadowing, key theft, cloned disks, snapshot restore, replay, time rollback, observer spoofing, identity collision, and remediation abuse.
- [ ] **SP-T007:** Decide hardware-backed key requirements and fallback assurance labels for macOS and Windows.
- [ ] **SP-T008:** Define privacy fields, audit retention, deletion, legal hold, tenant export, and data-residency requirements.
- [ ] **SP-T009:** Add architecture decisions for health identity/generation, independent observer trust, and remediation authority.

## P0: local machine self-protection

- [ ] **SP-T010:** Extend `guard/mdm/contracts.py` with typed snapshot, key-protection, supervisor, and reason-code contracts.
- [ ] **SP-T011:** Extend `guard/mdm/manifest.py` to verify the complete protected file set, native signature/package identity, manifest rollback, and manifest coverage gaps.
- [ ] **SP-T012:** Add platform-native ACL/owner verification for runtime, manifest, machine state, policy, device key, service registration, and logs.
- [ ] **SP-T013:** Add native service/launch-registration health checks using absolute machine-owned executable paths and bounded environments.
- [ ] **SP-T014:** Detect stopped/disabled supervisor, missing scheduled health runner, executable shadowing, downgrade, partial uninstall, and policy removal with stable reason codes.
- [ ] **SP-T015:** Add a read-only `hol-guard mdm integrity-snapshot --scope machine --json` command that works against partial state.
- [ ] **SP-T016:** Add aggregate per-user harness coverage to snapshots without usernames, home paths, tokens, or command content.
- [ ] **SP-T017:** Provision, rotate, and revoke a device signing key; prefer Keychain/TPM-backed non-exportable storage and report the protection level.
- [ ] **SP-T018:** Add monotonic sequence, installation generation, boot/session identity, and previous-lease digest state with atomic writes and rollback detection.
- [ ] **SP-T019:** Ensure user-managed installs report `assuranceLevel=user-managed` and never masquerade as machine protected.
- [ ] **SP-T020:** Harden managed uninstall/deactivation to consume a short-lived, generation-bound, single-use removal authorization and emit lifecycle evidence.
- [ ] **SP-T021:** Preserve a bounded machine audit tombstone across repair/reinstall without retaining secrets.

Likely working set: `src/codex_plugin_scanner/guard/mdm/`, CLI MDM parsers/dispatch, native packaging, managed-policy schemas, and platform key-storage adapters.

## P0: local lease reporter

- [ ] **SP-T022:** Add signed lease construction and strict schema validation in the Guard runtime.
- [ ] **SP-T023:** Bind each lease to workspace, device, machine installation, generation, sequence, issue/expiry time, and snapshot digest.
- [ ] **SP-T024:** Add a bounded lease outbox that retries current evidence but never backfills expired proof.
- [ ] **SP-T025:** Add a machine-context cadence runner independent of receipts, user sessions, and harness activity.
- [ ] **SP-T026:** Keep local enforcement independent of Cloud health and expose delivery failure without weakening policy.
- [ ] **SP-T027:** Add challenge-response support for Cloud-requested fresh attestation without creating a generic remote-command channel.
- [ ] **SP-T028:** Add metrics for snapshot duration, lease age, delivery latency, rejection reason, queue depth, and key-storage health.

Likely working set: a new `guard/protection/` package, `guard/schemas/`, Cloud connection/auth code, machine supervisor packaging, and structured diagnostics.

## P0: Guard Cloud ingestion and projection

- [ ] **SP-T029:** Add database migrations for installations/generations, leases, observer assertions, current protection state, transitions, removal authorizations, and remediation jobs.
- [ ] **SP-T030:** Implement a device-authenticated lease endpoint with strict size, identity, signature, sequence, generation, freshness, and rate-limit checks.
- [ ] **SP-T031:** Make lease ingestion idempotent and concurrency-safe; retain append-only evidence and update the current-state projection transactionally.
- [ ] **SP-T032:** Implement a scheduled expiry evaluator so absence is detected without a new inbound event.
- [ ] **SP-T033:** Reject replayed, duplicate, out-of-order, expired, future-dated, wrong-workspace, wrong-device, wrong-generation, and revoked-key leases.
- [ ] **SP-T034:** Add observer-authenticated assertion ingestion using credentials distinct from Guard device credentials.
- [ ] **SP-T035:** Implement explicit MDM/EDR device mapping with ambiguity quarantine and administrator reconciliation.
- [ ] **SP-T036:** Implement the complete protection state machine and reconstruct current state from append-only evidence in tests.
- [ ] **SP-T037:** Add workspace policy for cadence, grace, observer requirement, maintenance windows, severity floor, routing, and remediation mode.
- [ ] **SP-T038:** Mark old clients `legacy_unattested`; do not synthesize healthy leases from receipt activity.
- [ ] **SP-T039:** Expose device and fleet projections with local lease freshness, observer freshness, assurance level, state reason, remediation state, and last transition.

Guard Cloud counterpart working set: Guard API routes, database schema/migrations, device services/types, scheduled jobs, workspace policy, and fleet UI in the Cloud repository.

## P0: incident and evidence integration

- [ ] **SP-T040:** Add enterprise events for degraded, tampered, lease missed, unexpected absence, authorized removal, remediation, recovery, and retirement.
- [ ] **SP-T041:** Open one deduplicated incident per active device episode, including unconfirmed managed missed-lease incidents, and append state transitions rather than creating alert storms.
- [ ] **SP-T042:** Include last healthy evidence, observer evidence, removal state, remediation attempts, and recovery proof in the incident timeline.
- [ ] **SP-T043:** Add webhook, SIEM, email, and configured notification routing with delivery retry evidence.
- [ ] **SP-T044:** Add bounded suppressions and maintenance windows that preserve underlying state and require actor, reason, and expiry.
- [ ] **SP-T045:** Extend exports and evidence manifests with protection transitions and digests while preserving redaction rules.
- [ ] **SP-T046:** Add RBAC for viewing device evidence, authorizing removal, suppressing alerts, retiring devices, and requesting remediation.
- [ ] **SP-T047:** Add audit events for every failed authorization, mapping change, suppression, retirement, remediation request, and manual incident resolution.

## P0: independent MDM/EDR observer and remediation

- [ ] **SP-T048:** Publish a vendor-neutral observer assertion and remediation adapter contract.
- [ ] **SP-T049:** Build an adapter conformance harness with signed fixtures, clock skew, replay, duplicate, partial data, mapping collision, and outage cases.
- [ ] **SP-T050:** Implement and certify one Apple MDM adapter and one Windows MDM/Intune adapter.
- [ ] **SP-T051:** Report MDM/EDR integration freshness, last success/error, scope, credential expiry, and mapped/unmapped device counts.
- [ ] **SP-T052:** Restrict remediation to signed install, repair, policy refresh, service registration, and approved version convergence.
- [ ] **SP-T053:** Add remediation idempotency, expiry, target generation/version, bounded retries, backoff, timeout, and escalation.
- [ ] **SP-T054:** Ensure ambiguous device mappings, stale observer data, retired devices, and active removal workflows cannot trigger automatic reinstall.
- [ ] **SP-T055:** Require independent confirmation before `removed_authorized` and require healthy lease plus fresh observer assertion for managed recovery.
- [ ] **SP-T056:** Add an emergency workspace/global pause for automatic remediation without suppressing detection or evidence.

## P1: user-managed connected installations

- [ ] **SP-T057:** Add opt-in signed health leases with user-scoped keys and explicit lower-assurance labeling.
- [ ] **SP-T058:** Add owner notification for prolonged silence without representing it as confirmed deletion.
- [ ] **SP-T059:** Detect missing hooks/shims/state and shadowing whenever another Guard entry point remains available.
- [ ] **SP-T060:** Create a new installation generation after state loss or reinstall and prevent silent inheritance of old trust.
- [ ] **SP-T061:** Preserve a Cloud audit tombstone after user disconnect/uninstall according to workspace retention policy.
- [ ] **SP-T062:** Add UI explanations and recommended actions for `unknown`, `offline`, `unexpectedly_absent`, and `removed_authorized`.

## P1: operations and reliability

- [ ] **SP-T063:** Add dashboards for lease ingestion latency, expired leases, observer coverage/freshness, transition rate, incident latency, and remediation outcomes.
- [ ] **SP-T064:** Alert on ingestion lag, evaluator lag, signature rejection spikes, observer outage, mapping ambiguity, remediation loops, and notification failure.
- [ ] **SP-T065:** Add capacity and failure-mode tests for fleet-wide reconnects, Cloud outage recovery, delayed observer batches, and clock skew.
- [ ] **SP-T066:** Add key and observer-credential rotation/revocation runbooks and exercises.
- [ ] **SP-T067:** Add backup/restore and disaster-recovery tests proving state projections can be rebuilt from evidence.
- [ ] **SP-T068:** Add customer runbooks for confirmed deletion, false positive, expected offline, authorized removal, device transfer, and retirement.
- [ ] **SP-T069:** Add support diagnostics that disclose state/reason/evidence IDs but never keys, tokens, host secrets, or raw command data.

## Verification matrix

- [ ] **SP-T070:** Unit-test every local reason code and Cloud state transition.
- [ ] **SP-T071:** Property-test lease ordering, replay, idempotency, expiry, and generation monotonicity.
- [ ] **SP-T072:** Test manifest/ACL/service/key tamper and complete deletion as standard user and administrator on macOS and Windows.
- [ ] **SP-T073:** Test endpoint asleep/offline, Guard Cloud outage, proxy failure, MDM outage, and maintenance windows without false confirmed deletion.
- [ ] **SP-T074:** Test authorized uninstall, unauthorized deletion, partial removal, repair, reinstall, rollback, snapshot restore, and retirement end to end.
- [ ] **SP-T075:** Test cloned device identity, stolen lease payload, wrong workspace, observer spoofing, ambiguous mapping, and compromised adapter containment.
- [ ] **SP-T076:** Test that the health and observer endpoints cannot become generic command-execution paths.
- [ ] **SP-T077:** Verify critical incidents resolve only after the configured consecutive healthy leases and fresh observer evidence.
- [ ] **SP-T078:** Run the conformance matrix on real managed devices with at least two MDM vendors across Apple and Windows coverage.
- [ ] **SP-T079:** Run privacy/redaction, RBAC, retention, export-integrity, accessibility, and localization checks.
- [ ] **SP-T080:** Conduct an independent security review and red-team exercise before enforcement GA.

## Rollout

- [ ] **SP-T081:** Ship schemas and local reporting behind feature flags with no Cloud enforcement.
- [ ] **SP-T082:** Enable report-only Cloud projection for internal devices; compare inferred state to MDM truth.
- [ ] **SP-T083:** Pilot incident creation without automatic remediation and measure false-confirmed-absence rate.
- [ ] **SP-T084:** Pilot manual remediation, then opt-in automatic remediation by staged workspace/device rings.
- [ ] **SP-T085:** Publish GA support matrix, SLOs, known limits, adapter versions, and release evidence.
- [ ] **SP-T086:** Make managed protection enforcement default only after pilot success metrics and rollback exercises pass.
- [ ] **SP-T099:** Keep the 3.1 implementation in report-only alpha until the release gates pass; publish each approved iteration through the release-branch alpha workflow.

## Definition of done

- Standard users cannot change or remove certified machine-owned protection surfaces.
- Cloud detects confirmed unexpected absence from an independent fresh observer signal within the PRD objective.
- Offline and user-managed silent devices are not mislabeled as confirmed deletion.
- Authorized removal, unexpected deletion, repair, recovery, and retirement have complete redacted audit timelines.
- Automatic remediation works through an external control plane and cannot loop or target ambiguous/stale devices.
- All schemas, APIs, UI states, events, runbooks, SLOs, migrations, and real-device evidence are versioned and published.
- The release gates and acceptance criteria in the PRD pass in CI and the certified endpoint lab.
- The merged release-branch commit is available as a verified PyPI `3.1.0aN` artifact, while stable installations remain on the stable channel.
- Release automation remains outside the self-protection implementation diff unless a separate release-infrastructure task explicitly scopes it in.
