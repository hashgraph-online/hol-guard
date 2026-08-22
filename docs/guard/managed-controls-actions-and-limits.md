# Managed Controls Actions and Limits

This document is a shared release 3.0 contract for customer-facing actions, approval memory, compatibility aliases, and bounded payloads. The machine-readable limits live in `contracts/managed-controls/v1/limits.json`.

## Customer-facing outcomes

A Control Set offers four contextual outcomes:

| Product outcome | Canonical policy effect | Meaning |
|---|---|---|
| Permit | `allow` | Allow the contextual request only when no stronger protection blocks it. |
| Review | `review` | Pause and require an authorized decision. |
| Block | `block` | Deny the contextual request. |
| No contextual decision | `ignore` | Do not add a contextual outcome. Extension posture and existing runtime floors still apply. |

The product does not expose `warn` or `remember` as canonical Control Set outcomes.

- **Warn** is presentation behavior. When an existing flow requires a warning, it must compile to a representable effect and disclose that mapping. The release 3.0 compatibility mapping is Review with warning presentation.
- **Remember** is an approval-memory operation. It creates or updates a remembered decision with an explicit lifetime. It does not add a second policy action and cannot bypass a Local block, required floor, shared restriction, or managed restriction.

The wire and implementation contracts retain `allow`, `block`, `review`, and `ignore`. Product copy uses Permit, Block, Review, and No contextual decision.

## Accessibility and compatibility

Visible labels, descriptions, empty states, switch labels, dialog titles, screen-reader labels, and help text must use the same product vocabulary.

The following aliases remain valid:

- Local `/policy` remains a route alias for Rules & exceptions.
- Cloud `/guard/policy` remains a compatibility alias for Managed controls and Control Set authoring.
- Existing `GuardPolicy`, policy document, policy compiler, policy version, and policy bundle names remain valid technical contracts.
- Stored action values remain unchanged unless a versioned migration explicitly rewrites them.

Compatibility aliases must not create a second product model. They resolve to the same Control Set, Extension, permission, contextual rule, and remembered-decision objects.

## Bounded limits

Release 3.0 uses one shared limit source across Local and Cloud:

| Limit | Value | Enforcement boundary |
|---|---:|---|
| Catalog Extensions | 512 | Local catalog construction and Cloud catalog ingestion |
| Catalog payload bytes | 1,000,000 | Runtime API and Cloud ingestion |
| Control layers | 2 | Local resolver and mutation API |
| Controls per layer | 512 | Local resolver and mutation API |
| Total controls | 1,024 | Local resolver, API, Cloud compilation, and signing |
| Control Set contextual rules | 1,024 | Cloud validation before compilation and signing |
| Control Set Extension targets | 1,024 | Cloud validation before compilation and signing |
| Permissions per Extension | 512 | Local registry construction and Cloud ingestion |
| Resolution Extension IDs | 1,024 | Local evaluation |
| Resolution permission IDs | 1,024 | Local evaluation |
| Observations | 2,048 | Local evaluation and bounded diagnostics |
| Input text length | 256 | Identifiers and bounded control inputs |

Every boundary must be tested at limit minus one, limit, and limit plus one where the representation permits it. API metadata must advertise the same values that the resolver, mutation service, compiler, and signer enforce.

Oversized data is rejected before signing, persistence, or enforcement. Clients must not silently truncate a Control Set or catalog in a way that could imply complete enforcement.

## Failure behavior

- Local resolution fails closed when a control input exceeds a security-relevant limit.
- Guard Cloud rejects an oversized Control Set before generating a signature or deployment.
- Cloud catalog ingestion rejects an oversized or malformed payload without replacing the last known-good catalog.
- Product surfaces show the violated limit and a safe reduction path. They do not describe Local protection as expired or disabled.
- A compatibility alias never weakens validation or bypasses the canonical compiler.

## Release checks

The release pipeline must prove:

1. The Local machine-readable fixture matches runtime constants.
2. The Cloud machine-readable fixture matches TypeScript constants.
3. Shared fixtures are byte-identical across repositories.
4. Runtime API metadata matches enforced values.
5. The bundle compiler validates limits before hashing and signing.
6. User-facing action choices map only to canonical effects.
7. Approval memory is described separately from Control Set outcomes.
8. Visible and accessible labels agree.
