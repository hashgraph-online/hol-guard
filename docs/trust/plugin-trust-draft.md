# HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT

## Scope

This local draft defines trust attribution for top-level Codex plugins.

## Why this exists

The scanner’s quality grade remains useful for gating, but it is not a trust specification. This draft explains how the scanner computes a separate plugin trust score with explicit weights and named evidence so contributors can see exactly how signals such as `SECURITY.md` affect the outcome.

## Adapters

### `verification` weight `1.0`

Internal component weights:

- `manifestIntegrity`: `35`
- `interfaceIntegrity`: `25`
- `pathSafety`: `20`
- `marketplaceAlignment`: `20`

### `security` weight `1.0`

Internal component weights:

- `disclosure`: `15`
- `license`: `10`
- `secretHygiene`: `35`
- `mcpSafety`: `20`
- `approvalHygiene`: `20`

`SECURITY.md` is deliberately only one small part of the security adapter. It is not intended to dominate trust on its own.

### `metadata` weight `0.75`

Internal component weights:

- `documentation`: `20`
- `manifestMetadata`: `35`
- `discoverability`: `20`
- `provenance`: `25`

### `operations` weight `0.75`

Internal component weights:

- `actionPinning`: `35`
- `permissionScope`: `20`
- `untrustedCheckout`: `25`
- `updateAutomation`: `20`

## Normalization

The scanner emits a weighted adapter `score` plus component-level evidence, then normalizes the adapter total as the average of declared components. The final plugin trust score is the weighted average of adapter totals.
