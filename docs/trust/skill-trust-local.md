# HCS-28 Skill Trust Alignment

## Scope

`codex-plugin-scanner` uses the published HCS-28 baseline adapter catalog for bundled Codex skills. The scanner does not define a private skill trust profile. Instead, it computes local bundled-skill evidence using the HCS-28 adapter ids, weights, contribution modes, and aggregation rules.

## Normative provenance

- Specification: `HCS-28`
- Specification version: `0.1`
- Profile: `hcs-28/baseline`
- Related publication model: `HCS-26`

The normative adapter ids and weights come directly from HCS-28:

| Adapter ID | Weight | Contribution Mode |
| --- | --- | --- |
| `verification.review-status` | `0.50` | `universal` |
| `verification.publisher-bound` | `0.20` | `universal` |
| `verification.repo-commit-integrity` | `0.40` | `universal` |
| `verification.manifest-integrity` | `0.30` | `universal` |
| `verification.domain-proof` | `0.10` | `universal` |
| `metadata.links` | `0.30` | `universal` |
| `metadata.description` | `0.25` | `universal` |
| `metadata.taxonomy` | `0.20` | `universal` |
| `metadata.provenance` | `0.25` | `universal` |
| `upvotes` | `1.00` | `conditional` |
| `safety.cisco-scan` | `1.00` | `universal` |
| `repository.health` | `1.00` | `conditional` |

## Local read-mode mapping

The scanner runs bundled skill trust in read mode with `includeExternal=false`. That means the HCS-28 aggregation algorithm stays the same, but local evidence substitutes for external refresh-only signals where possible.

Local bundled-skill normalization:

- `verification.review-status`: `100` only when the local bundled skill package explicitly declares `verified=true`; otherwise `0`
- `verification.publisher-bound`: `100` when plugin author metadata exists
- `verification.repo-commit-integrity`: `100` when bundled skill metadata declares both `repo` and `commit`
- `verification.manifest-integrity`: `100` when every bundled `SKILL.md` parses and includes required frontmatter fields
- `verification.domain-proof`: `100` when homepage and repository hosts align
- `metadata.links`: exact HCS-28 baseline rule
- `metadata.description`: exact HCS-28 description-length thresholds
- `metadata.taxonomy`: exact HCS-28 tag-count and language-count matrix
- `metadata.provenance`: exact HCS-28 repo/commit rule
- `upvotes`: omitted in the denominator unless a local upvote count is provided
- `safety.cisco-scan`: exact HCS-28 severity normalization when Cisco results exist; otherwise universal `0`
- `repository.health`: omitted in read mode unless a persisted external score exists

## Aggregation

The scanner follows HCS-28 normalization and denominator rules exactly:

1. Clamp emitted component values to `[0,100]`.
2. Materialize missing universal components as `0`.
3. Compute each adapter total as the arithmetic mean of its component values.
4. Include conditional adapters in the denominator only when they emit scores.
5. Compute the composite total as the weighted mean of included adapter totals.

This keeps bundled skill trust explainable and directly comparable to the published HCS-28 baseline semantics without referencing private registry implementation details.
