# HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT

## Scope

This local draft defines trust attribution for top-level Codex plugins using the same HCS-style structure as HCS-28: single-score adapters, explicit weights, explicit contribution modes, and deterministic denominator rules.

## Subject model

The scored subject is one top-level Codex plugin rooted at a plugin directory.

## Scoring profile

- Profile id: `hol-codex-plugin-trust/baseline`
- Profile version: `0.1`
- Execution modes:
  - read mode: `includeExternal=false`
  - refresh mode: reserved for future external provenance checks

## Adapter contract

Each adapter emits exactly one score key named `<adapterId>.score`.

## Baseline adapter catalog

| Adapter ID | Weight | Contribution Mode |
| --- | --- | --- |
| `verification.manifest-integrity` | `0.35` | `universal` |
| `verification.interface-integrity` | `0.25` | `conditional` |
| `verification.path-safety` | `0.20` | `universal` |
| `verification.marketplace-alignment` | `0.20` | `conditional` |
| `security.disclosure` | `0.15` | `universal` |
| `security.license` | `0.10` | `universal` |
| `security.secret-hygiene` | `0.35` | `universal` |
| `security.mcp-safety` | `0.20` | `conditional` |
| `security.approval-hygiene` | `0.20` | `universal` |
| `metadata.documentation` | `0.15` | `universal` |
| `metadata.manifest-metadata` | `0.2625` | `universal` |
| `metadata.discoverability` | `0.15` | `universal` |
| `metadata.provenance` | `0.1875` | `universal` |
| `operations.action-pinning` | `0.2625` | `universal` |
| `operations.permission-scope` | `0.15` | `universal` |
| `operations.untrusted-checkout` | `0.1875` | `universal` |
| `operations.update-automation` | `0.15` | `universal` |

## Interpretation

`SECURITY.md` now has one explicit weight: `security.disclosure = 0.15`. It no longer sits inside an opaque grouped adapter. Contributors can see its contribution directly relative to stronger signals such as `security.secret-hygiene = 0.35`, `verification.manifest-integrity = 0.35`, and `operations.action-pinning = 0.2625`.

## Aggregation

The scanner uses the same aggregation pattern as HCS-28:

1. clamp emitted scores to `[0,100]`
2. materialize missing universal adapter scores as `0`
3. include conditional adapters only when their subject actually exposes the corresponding surface
4. compute the final plugin trust score as the weighted mean of the included adapter totals
