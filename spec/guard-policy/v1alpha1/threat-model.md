# GuardPolicy v1alpha1 threat model

## Assets and boundaries

Protected assets are effective decisions, policy provenance, canonical bytes and hashes, signing keys, trusted verification keys, rollback state, local SQLite policy rows, and cloud synchronization acknowledgements.

The YAML file is untrusted input. The Portal API, transport, local cache, and extension values are also untrusted until schema validation, canonicalization, signature verification, trust anchoring, and rollback checks complete. Local runtime enforcement remains authoritative when cloud policy is unavailable or invalid.

## Threats and required controls

| Threat | Required control |
| --- | --- |
| YAML aliases, merge keys, custom tags, duplicate keys, or parser differentials | Reject before semantic conversion; use the documented YAML subset and fixture suite. |
| Oversized or deeply nested policy | Enforce byte, depth, collection, string, and rule-count limits before expensive work. |
| Unknown core field or action | Fail closed for the document; never discard and continue enforcement. |
| Extension collision or semantic smuggling | Restrict names to registered `x-` keys; include extension values in canonical bytes; extensions cannot override core semantics. |
| Canonicalization disagreement | Hash and sign RFC 8785 canonical JSON only; verify published byte and digest vectors. |
| Signature substitution or key injection | Verify RSA-PSS/SHA-256 with an independently trusted key registry; never trust an envelope's embedded key by itself. |
| Replay, downgrade, or unauthorized rollback | Persist the last accepted version/hash, reject lower or conflicting versions, and require explicit signed rollback authorization. |
| Partial cloud update or concurrent Portal writer | Use atomic compare-and-swap revision writes; never merge canonical and legacy authorities after validation. |
| Expired temporary rule | Evaluate expiry before precedence and exclude expired rows. |
| Broad remote policy eclipses exact local intent | Apply documented eligibility, authority, specificity, and recency precedence in that order. |
| Secret disclosure through policy, diagnostics, or logs | Reject secret-bearing fields, redact parser errors, and log bounded reason codes rather than raw policy content. |
| Client capability spoofing | Capability negotiation selects serialization only; it does not grant policy authority or weaken local trust checks. |
| Availability loss during rollout | Preserve byte-identical bundle v1 fallback and last-known-good local policy; fail closed for unverified v2 without deleting the valid cache. |

## Signing-key handling

Portal private signing keys remain outside policy documents and source control. Bundles identify a key; Guard resolves that identifier through its trusted-key registry. Revocation and grace state are local trust decisions. Signatures cover the canonical envelope payload and all extension values.

## Privacy

Policy matchers may reveal repository, path, package, tool, device, or workspace identifiers. Implementations minimize transport and logs, never include raw secrets, and keep local-only rules local unless the user explicitly synchronizes them.

## Non-goals

The format does not make a malicious endpoint trustworthy, replace operating-system isolation, authorize cloud enrollment, or guarantee that every harness exposes every action. It standardizes policy meaning and transport for supported enforcement surfaces.

## Residual risk and stabilization gate

Parser bugs, implementation-specific Unicode behavior, incomplete harness coverage, and ambiguous new vocabularies remain alpha risks. v1.0 requires independent fixture agreement, no unexplained decision mismatch in staged production, and dedicated security review of parsing, signatures, rollback, precedence, and secret handling.
