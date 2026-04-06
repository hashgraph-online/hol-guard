# HOL-HCS-28-SKILL-TRUST-LOCAL-DRAFT

## Scope

This local draft defines how `codex-plugin-scanner` attributes trust to bundled Codex skills before those skills are published into the HOL skill registry.

## Provenance

This model inherits its adapter shape and weights from the live HOL broker implementation that scores published HCS-26 skills:

- `verified` adapter weight: `1.0`
- `safety` adapter weight: `1.0`
- `metadata` adapter weight: `0.75`

The scanner keeps those adapter weights and component names so local scores can be compared to registry scores later. It does not use registry cohort normalization locally because a single plugin checkout has no comparable cohort.

## Adapter definitions

### `verified`

Internal component weights:

- `publisherBound`: `20`
- `repoCommitIntegrity`: `40`
- `manifestIntegrity`: `30`
- `domainProof`: `10`

Local mapping:

- `publisherBound`: plugin author metadata exists for the bundled skill package
- `repoCommitIntegrity`: repository metadata plus semver version exists locally
- `manifestIntegrity`: every bundled `SKILL.md` parses frontmatter with required fields
- `domainProof`: homepage and repository hosts align

### `safety`

- single `score` component
- backed by Cisco skill scanning when available
- falls back to a neutral local score when the optional Cisco dependency is unavailable

### `metadata`

Internal component weights:

- `links`: `30`
- `description`: `25`
- `taxonomy`: `20`
- `provenance`: `25`

Local mapping:

- `links`: homepage and repository metadata for the bundled skill package
- `description`: average bundled skill description quality
- `taxonomy`: category and tag coverage
- `provenance`: repository and version provenance present locally

## Normalization

Each adapter emits a weighted `score` plus component-level signals. The scanner normalizes the adapter the same way the broker does today: it averages the declared adapter components, then computes the final trust total as the weighted average of adapter totals.
