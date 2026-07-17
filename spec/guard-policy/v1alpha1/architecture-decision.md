# Architecture decision: canonical GuardPolicy document

Status: accepted for V3 alpha integration

## Context

Portal Policy Builder, Suggested Memory, signed cloud bundles, and local HOL Guard previously represented policy through related but independently evolving payloads. Enforcement could combine those payloads, but identity, provenance, canonical hashing, capability negotiation, and rollback were not one explicit contract.

## Decision

- `guard.hashgraphonline.com/v1alpha1` is the shared portable policy contract.
- YAML is human input and display only. Validated typed data is the semantic model.
- RFC 8785 canonical JSON is the sole hashing and signing representation.
- Stable rule IDs preserve identity across Builder, Suggested Memory, migration, sync, and local evaluation.
- Portal remains the authority for cloud-owned policy; local policy retains its documented precedence and fallback behavior.
- Bundle v2 signs the complete manifest and payload and activates only after capability negotiation, validation, shadow equivalence, and acknowledgement.
- Bundle v1 and legacy fields remain available throughout the measured compatibility window.
- Canonical and legacy last-known-good state is retained independently so rollback does not depend on the rejected candidate.
- Rollout uses deterministic workspace-and-device cohorts and one legacy kill switch. Canonical enforcement is off by default in the V3 alpha artifact.

## Consequences

- Both implementations must consume the same schema and conformance fixtures.
- Unsupported semantics fail closed rather than silently downgrade.
- Policy parsing and compilation occur at write, import, or sync time rather than interception time.
- Observability is limited to bounded reason codes, counts, versions, and hashes; raw policy content is excluded.
- Promotion means merge into `release/3.1` plus alpha artifact verification. Integration into `main`, stable PyPI publication, and default runtime activation remain separate decisions.
- Removing bundle v1, legacy reads, or legacy storage requires capability coverage, a clean observation window, exercised rollback, and a separately approved proposal.

## Rejected alternatives

- Hashing YAML bytes: presentation differences would change identity without changing semantics.
- Treating Suggested Memory as an independent rule store: duplicate authorities would preserve drift and unstable identity.
- Partial canonical cutover by rule: mixing an incomplete canonical subset with complete legacy policy can change enforcement.
- Flag-only bundle selection: flags do not prove client parser, signature, acknowledgement, rollback, or snapshot support.
- Destructive migration: it removes the exact rollback path required during alpha adoption.
