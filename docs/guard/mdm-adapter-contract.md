# HOL Guard MDM/EDR adapter contract

Status: report-only alpha for release 3.1. This contract is vendor-neutral. Vendor names, API
objects, package queries, and deployment commands belong in adapter implementations, not Guard
core.

## Trust boundaries

- Observer adapters use workspace-scoped observer credentials distinct from endpoint device keys.
- Remediation adapters accept only Cloud-signed `remediation-job.v1` envelopes from the approved
  workspace authority. An observer credential cannot authorize remediation.
- Adapters never accept a shell command, script body, URL-selected executable, or arbitrary
  package identifier from a job.
- Every vendor device identity maps explicitly to exactly one Guard installation generation.
  Zero or multiple candidates are quarantined and cannot trigger automatic remediation.
- An adapter outage produces integration-health evidence only. It must not synthesize package
  absence, endpoint presence, or successful remediation.

## Observer output

Each observation is canonical UTF-8 JSON matching
[`observer-assertion.v1`](schemas/observer-assertion.v1.schema.json). The Ed25519 signature covers
the complete envelope except `signature`, serialized with sorted keys and compact separators.
Adapters must provide:

- stable workspace, observer, adapter, and external-device identifiers;
- observation and expiry timestamps in UTC;
- endpoint online state when the vendor can establish it;
- detected package identity and version, or explicit nulls when unknown;
- `present`, `absent`, `partial`, `unknown`, or `unsupported` detection state;
- at least one bounded reason code for partial evidence; and
- remediation state tied to a job identifier whenever the state is not `none`.

Guard Cloud accepts at most 60 seconds of future clock skew and a 15-minute assertion lifetime.
An exact `(observerId, assertionId, digest)` replay is idempotent. Reusing the identifier with a
different digest is rejected. Freshness is based on signed observation time, never HTTP receipt
time.

## Remediation input

Adapters accept canonical signed
[`remediation-job.v1`](schemas/remediation-job.v1.schema.json) only. Allowed actions are:

- `install`
- `repair`
- `policy-refresh`
- `service-register`
- `version-converge`

`install` and `version-converge` require an approved target version. The adapter resolves that
version through its pinned signed release channel; it does not execute caller-provided content.
Jobs bind workspace, device, installation generation, idempotency key, issue time, expiry, and
attempt limit. Exact retries are idempotent. A key reused for a changed target, action, generation,
or payload is a conflict. Adapters report only `accepted`, `running`, `succeeded`, `failed`,
`unsupported`, or `timed-out`; bounded retries and escalation remain Cloud policy.

## Conformance harness

`codex_plugin_scanner.guard.mdm.adapter_conformance` is the executable reference boundary. Adapter
certification must feed the adapter's real canonical envelopes and configured public keys through
both harnesses. The matrix must pass:

| Case | Required result |
| --- | --- |
| Valid signed observation | accepted |
| Exact duplicate | duplicate, same digest |
| Same assertion ID with changed payload | replay conflict |
| Invalid signature | rejected |
| Future clock beyond skew | rejected |
| Expired or overlong evidence | rejected |
| Partial data without reason | rejected |
| Zero or multiple mapping candidates | quarantined |
| Vendor timeout/outage | outage, no assertion digest |
| Valid signed allowlisted remediation | accepted |
| Exact remediation retry | duplicate |
| Changed payload under one idempotency key | replay conflict |
| Arbitrary action, expired job, or wrong generation shape | rejected |

Passing the in-process harness proves contract compatibility, not production certification. Apple
and Windows certification additionally requires real managed-device runs, least-privilege vendor
credentials, vendor audit logs, signed installer verification, and retained redacted evidence.
