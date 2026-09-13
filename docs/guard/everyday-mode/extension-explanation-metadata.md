# Extension explanation metadata

Command extensions may contribute presentation metadata to Everyday Mode, but they never acquire enforcement authority from that metadata.

## Allowed metadata

The versioned explanation metadata schema supports an everyday name and purpose for an extension; search and technical synonyms; applicable dialects; and per-rule action-intent IDs, target-kind IDs, consequence IDs, safer-step IDs, optional safe-variant IDs, and minimum confidence.

External values are length bounded and pass through Guard redaction. Signed metadata is accepted only after the caller verifies its signature and then the explanation parser enforces schema version and monotonic revision. Rollback revisions are rejected.

## Enforcement boundary

Explanation metadata cannot emit or override `action`, `policy_action`, `enforcement`, `decision`, `verdict`, allow/deny/block fields, or equivalent nested fields. The parser rejects these recursively. Metadata also cannot suppress every consequence for a rule. The existing command extension registry, permission catalog, policy engine, and action pipeline remain authoritative.

## Coverage

Every built-in command rule must have an explanation metadata path or an explicit generic fallback before release. This prevents a newly shipped enforcement rule from silently falling back to raw command text in Everyday surfaces.

## Digest

The explanation metadata catalog has its own deterministic digest. `explanation_catalog_digest()` binds that digest to the authoritative command extension catalog digest so stale presentation metadata can be detected without using raw action content.
