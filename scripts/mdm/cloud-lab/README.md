# HOL Guard multi-device MDM Cloud integration lab

This directory contains the provider-neutral integration lab for HOL Guard 3.0 MDM control. It runs a stateful Cloud service, a deterministic fault proxy, three independently keyed HOL Guard device runtimes, and a fleet orchestrator over real HTTP.

## Run

From the repository root:

```bash
python scripts/mdm/run-cloud-integration-lab.py
```

Dry-run the exact Compose commands:

```bash
python scripts/mdm/run-cloud-integration-lab.py --dry-run
```

Keep the project after a failure for inspection:

```bash
python scripts/mdm/run-cloud-integration-lab.py --keep
```

Write the canonical report to a chosen path:

```bash
python scripts/mdm/run-cloud-integration-lab.py \
  --artifacts artifacts/mdm-cloud-lab
```

The runner creates a unique Compose project, builds from the current worktree, waits on service healthchecks, runs the one-shot orchestrator, validates the report, and removes containers, networks, and volumes unless `--keep` is supplied.

## Services

- `cloud`: signed desired state, enrollment, assignments, acknowledgements, health, remediation, audit, and SQLite durability.
- `fault-proxy`: partitions, delays, forced status, drops, corruption, truncation, stale replay, and ETag removal.
- `device-a`, `device-b`, `device-c`: separate device keys, generations, policy files, checkpoints, outboxes, and fault controls.
- `orchestrator`: baseline, canary, skipped revision, rollback, crash, replay, partition, corruption, clock, cloning, remediation, and privacy assertions.

## Fast tests without Docker

```bash
PYTHONPATH=src pytest -q \
  tests/test_guard_mdm_cloud_control.py \
  tests/test_guard_mdm_cloud_schemas.py \
  tests/test_guard_mdm_cloud_lab_integration.py \
  tests/test_guard_mdm_cloud_lab_registration.py
```

The integration test starts real HTTP servers and the real SQLite store in one Python process. It exercises the same orchestrator and production managed-policy parser, but it does not prove container isolation.

## Add a regression

1. Add the smallest deterministic fault needed to `fault_proxy.py` or `device_runtime.py`.
2. Add a named orchestrator assertion with bounded evidence.
3. Add a focused unit test for the security rule.
4. Update the report schema only when the external report contract changes.
5. Update the PRD/TODO only when scope or certification boundaries change.
6. Preserve the native-certification `not-evaluated` statement.

## Security boundary

The reference Cloud is test infrastructure, not a production Cloud replacement. The lab proves provider-neutral policy and evidence behavior. It does not certify native Apple or Windows management transports, OS key stores, package signing, or commercial MDM behavior.
