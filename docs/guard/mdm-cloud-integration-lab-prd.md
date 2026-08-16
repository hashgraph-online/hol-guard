# PRD: HOL Guard multi-device MDM Cloud integration hardening

## Status

Implementation complete for the provider-neutral control plane and Docker lab. Native certification remains a separate, explicitly unevaluated release gate.

## Problem

The existing portable MDM lab verifies contracts and local behavior, but it does not prove that several independent HOL Guard devices can enroll, receive Cloud-managed desired state, survive partial rollout and network faults, durably acknowledge application, publish monotonic health evidence, and execute only typed remediation. A green unit suite is not sufficient when failures can occur between Cloud persistence, delivery, local atomic writes, acknowledgement delivery, or recovery after a crash.

## Goal

Provide a deterministic integration environment that uses real HTTP, durable Cloud state, unique device keys, isolated device volumes, signed configuration, a fault-injection proxy, and a fleet orchestrator. The same tests must run quickly in-process and as separate Docker services in CI.

## Users

- Security engineering validating endpoint-management guarantees.
- CISOs and CSOs relying on fleet posture and rollout evidence.
- Release engineers certifying HOL Guard 3.0.
- Adapter authors mapping Intune, Jamf, Kandji, Workspace ONE, or another MDM to the vendor-neutral contract.

## Research-derived principles

1. Device identity is independent of user identity and network location. Every runtime request is bound to the device key, workspace, installation generation, HTTP method, path, body hash, time, and monotonic sequence.
2. Desired state is declarative. Cloud signs a complete configuration envelope; devices validate and converge rather than accepting an arbitrary command stream.
3. Fleet assignment is per device. A canary may skip global revisions, so the predecessor hash must be recorded per assignment rather than assumed globally.
4. Delivery is at least once. Acknowledgements, health evidence, and remediation results require durable device outboxes and Cloud idempotency.
5. Local enforcement survives Cloud failure. A partition never weakens the last known good managed policy.
6. Native transport certification is distinct from provider-neutral correctness.

## Architecture

The Compose project contains:

- `cloud`: SQLite-backed enrollment, assignment, acknowledgement, health, remediation, and audit service.
- `proxy`: deterministic partitions, delay, forced status, connection drops, corruption, truncation, stale replay, and ETag removal.
- `device-a`, `device-b`, `device-c`: independent P-256 keys, installation generations, policy files, checkpoints, proof sequences, and outboxes.
- `orchestrator`: publishes baseline and canary policy, injects failures, drives recovery, and writes a bounded evidence report.

The network is internal, has no host ports, mounts no Docker socket, drops capabilities, uses read-only root filesystems and tmpfs, applies health-gated startup, and places every device on a separate persistent volume.

## Security contracts

### Enrollment

Enrollment is one time and bound to workspace, device, installation generation, and P-256 public key. Cloud stores only a SHA-256 token digest. Reuse, key cloning, and identity collision fail closed.

### Request proof

Every post-enrollment request is signed by the device key. The proof covers method, path, body hash, request time, and sequence. Cloud rejects missing proof, bad signatures, stale time, wrong workspace or generation, and any sequence not greater than the stored sequence.

### Configuration

Cloud signs exact `hol-guard-mdm-cloud-config.v1` envelopes with RSA-PSS SHA-256. The envelope binds identity, revision, validity, policy, policy hash, predecessor hash, rollback metadata, and signing key. The device verifies the envelope and then invokes the existing `hol-guard-mdm-policy.v1` parser before writing policy.

### Atomic apply and recovery

The device persists a pending record, atomically replaces the policy file with restrictive permissions, commits its revision checkpoint, and queues an acknowledgement. A crash after the policy rename is recovered from the pending record without silently losing the acknowledgement.

### Health

Health is sequence-bound and reports the applied revision and policy hash. Offline reports stay in a durable outbox. Cloud rejects sequence replay and identity substitution.

### Remediation

Cloud can issue only `integrity-scan`, `policy-refresh`, `repair`, `service-register`, or `version-converge`, each with a strict parameter schema, bounded validity, bounded attempts, and idempotency key. Arbitrary commands, scripts, shells, URLs, credentials, and unknown fields are rejected.

## Required scenarios

The orchestrator must prove:

- Three independent enrollments and keys.
- Baseline rollout to all devices.
- Canary rollout to one device while others remain anchored.
- Per-device predecessor chains across skipped revisions.
- Configuration corruption rejection and later convergence.
- Network partition with local continuity and catch-up.
- Request-proof replay rejection.
- Workspace substitution rejection.
- Stale configuration replay rejection.
- Explicit signed rollback with monotonic revision.
- Crash after policy write and durable recovery.
- Durable acknowledgement and health outboxes.
- Typed remediation completion.
- Arbitrary-command rejection.
- Audit and report redaction.

## Evidence

The lab emits `hol-guard-mdm-cloud-integration-lab.v1` containing a bounded list of named steps, pass status, duration, evidence, workspace, and an explicit native-certification section. CI validates the schema, uploads the report, captures bounded Compose logs on failure, and always removes containers, networks, and volumes.

## Acceptance criteria

- Contract and schema tests pass.
- The in-process real-HTTP integration passes with at least 25 assertions.
- The Docker Compose project exits successfully through the orchestrator.
- Every report step passes.
- The report states native certification is `not-evaluated`.
- No arbitrary remote command surface exists.
- Cloud state and evidence contain no enrollment token, private key, credential, or unbounded error material.
- The task ledger contains at least 300 unique tasks and preserves unfinished native/provider gates honestly.

## Native certification boundary

This lab does not certify APNs, Apple supervision, Automated Device Enrollment, Secure Enclave behavior, Windows CSP/SyncML enrollment, SYSTEM context, Authenticode, WDAC, production package signing, notarization, or a commercial provider's retries, RBAC, scheduling, and audit export. Those remain release-candidate tests on native platforms or provider trials and must never be inferred from Docker success.
