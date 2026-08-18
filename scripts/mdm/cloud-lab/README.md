# HOL Guard multi-device MDM Cloud integration lab

This directory contains the provider-neutral integration lab for HOL Guard 3.0 MDM control. It runs a persistent reference Cloud service, a deterministic fault proxy, four independently keyed HOL Guard device runtimes across two workspaces, and a fleet orchestrator over real HTTP.

## Run

From the repository root:

```bash
python scripts/mdm/run-cloud-integration-lab.py
```

The runner builds the current worktree, starts the control plane and devices, executes the initial security matrix, restarts Cloud and every device, executes persistence checks, validates the report, writes a SHA-256 checksum, captures bounded logs, and tears down the entire Compose project.

Useful modes:

```bash
python scripts/mdm/run-cloud-integration-lab.py --dry-run
python scripts/mdm/run-cloud-integration-lab.py --keep
python scripts/mdm/run-cloud-integration-lab.py \
  --artifacts artifacts/mdm-cloud-lab
```

## Services

- `volume-init`: grants the fixed unprivileged lab identity access only to named state and evidence volumes.
- `cloud`: signed desired state, one-time enrollment, assignments, historical acknowledgements, health, remediation, audit, and SQLite durability.
- `proxy`: partitions, throttling, forced status responses, request drops, lost success responses, corruption, truncation, malformed JSON, stale replay, and ETag removal.
- `device-a`, `device-b`, `device-c`: independent machines in the alpha workspace.
- `device-d`: an independent machine in a second workspace for tenant isolation.
- `orchestrator`: enrollment, baseline, canary, skipped revisions, rollback, crash recovery, replay, partition, corruption, idempotency, fixed remediation, evidence verification, restart, and privacy assertions.

All runtime services use UID and GID `10001`, read-only root filesystems, dropped capabilities, no-new-privileges, internal-only networking, bounded memory and CPU, and separate persistent volumes. The project exposes no host ports and does not mount the Docker socket.

## Fast tests without Docker

```bash
PYTHONPATH=src:scripts/mdm/cloud-lab pytest -q \
  tests/test_guard_mdm_cloud_control.py \
  tests/test_guard_mdm_cloud_hardening.py \
  tests/test_guard_mdm_cloud_schemas.py \
  tests/test_guard_mdm_cloud_lab_integration.py \
  tests/test_guard_mdm_cloud_lab_registration.py
```

The real-HTTP test starts the same Cloud, proxy, and four device implementations in one Python process. It stops and recreates all servers against the same state directories before the restart phase. The Docker gate additionally proves container isolation, named-volume permissions, unprivileged execution, and evidence export.

## Security invariants

- Enrollment is one-time and bound to workspace, device, installation generation, and a unique P-256 key.
- Every runtime request binds method, path, body digest, timestamp, device identity, and a persistent monotonic sequence.
- Desired state is RSA-PSS signed and binds identity, revision, policy hash, predecessor hash, validity, and rollback metadata.
- A newer revision is visible even when its policy bytes match an earlier revision.
- Devices retain the last known good policy whenever Cloud, transport, signature, JSON, ETag, or policy validation fails.
- Historical acknowledgements remain valid after a newer assignment is published.
- Outboxes remove an item only after delivery or a proven exact duplicate. Ambiguous `409`, `429`, `503`, and lost-response outcomes remain retryable.
- Remediation is limited to a fixed typed action set. Arbitrary commands, scripts, shells, URLs, credentials, and open parameter bags are rejected.
- Local execution success remains `awaiting_evidence` until a later healthy report proves recovery.
- Audit details are redacted and linked by a tamper-evident hash chain.
- Workspace-scoped state cannot reveal or control another tenant.

## Certification boundary

The lab proves the HOL Guard-owned provider-neutral control and evidence path. It does not certify Apple APNs, Automated Device Enrollment, supervision, notarization, Windows OMA-DM/CSP, SYSTEM execution, Authenticode, WDAC, or any commercial provider. Those gates remain explicitly `not-evaluated` until executed on the actual platform or provider.
