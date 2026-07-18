# ADR 0002: Self-protection evidence and remediation authority

Status: accepted for `release/3.1` report-only alpha.

## Context

A Guard process can report its own health but cannot prove that it still exists after it has been deleted. MDM and EDR systems can independently observe and repair an endpoint, but their credentials and device identifiers differ by vendor. Health, observation, removal, and remediation therefore require separate identities and narrowly bounded authority.

## Decision

- A stable workspace/device relationship may contain multiple machine installation generations. State loss, reinstall, untrusted key replacement, clone collision, or rollback creates a new generation; it never inherits an old generation's trust.
- A device key is scoped to one workspace, device, machine installation, and generation. It signs only the local snapshot/lease domain. Hardware-backed non-exportable storage is the managed target; fallback storage lowers assurance.
- Observer credentials are separate from device credentials. They are scoped to one organization/workspace, adapter instance, vendor tenant, and approved external-device identifiers. They sign only observer assertions.
- Explicit mapping records connect external device identifiers to Guard devices. Ambiguous mappings are quarantined and cannot confirm deletion or trigger remediation.
- Removal authority belongs to an RBAC-authorized workspace/MDM administrator and is represented by a signed, short-lived, single-use, operation- and generation-bound authorization.
- Remediation authority belongs to a separately authenticated adapter. Guard Cloud issues only signed, expiring, idempotent allowlist jobs for install, repair, policy refresh, service registration, and approved version convergence. The contract has no shell command or arbitrary argument field.
- Guard Cloud is the ordering and projection authority. It preserves append-only evidence and transitions, applies server bounds, and resolves incidents only after configured recovery evidence.
- Health and challenge endpoints return bounded contracts and cannot carry generic remote commands or policy weakening instructions.

## Consequences

Machine reporting requires enrollment of the device public key and generation before Cloud acceptance. Observer integrations require explicit credentials and mapping operations instead of embedding vendor logic in Guard core. Recovery and authorized removal require independent evidence. Compromise of one authority does not automatically grant another authority.

The normative guarantee, schema set, state precedence, bounds, key assurance, privacy rules, and authority matrix are in [the self-protection contract](../self-protection-contract.md). Abuse analysis is in [the self-protection threat model](../self-protection-threat-model.md).

