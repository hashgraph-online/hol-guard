# HOL-HCS-MCP-TRUST-DRAFT

## Scope

This local draft defines trust attribution for Codex plugin `.mcp.json` configuration using the same scoring shape as HCS-28: one adapter per externally reported score key, explicit contribution modes, and weighted denominator rules.

## Subject model

The scored subject is one Codex plugin MCP configuration rooted at a plugin directory.

## Scoring profile

- Profile id: `hol-hcs-mcp-trust/baseline`
- Profile version: `0.1`
- Execution modes:
  - read mode: `includeExternal=false`
  - refresh mode: reserved for future external MCP probes

## Adapter contract

Each adapter emits exactly one score key named `<adapterId>.score`.

## Baseline adapter catalog

| Adapter ID | Weight | Contribution Mode | Local rule |
| --- | --- | --- | --- |
| `verification.config-integrity` | `0.40` | `universal` | `100` when `.mcp.json` parses, else `0` |
| `verification.execution-safety` | `0.35` | `universal` | uses the scanner dangerous-command check |
| `verification.transport-security` | `0.25` | `universal` | uses the scanner hardened-remote check |
| `metadata.server-naming` | `0.1875` | `universal` | `100` when every MCP surface is explicitly named |
| `metadata.command-or-endpoint` | `0.3375` | `universal` | `100` when every MCP surface declares a concrete command or secure endpoint |
| `metadata.config-shape` | `0.225` | `universal` | `100` when top-level containers match the expected shape |

## Aggregation

The scanner uses the same aggregation pattern as HCS-28:

1. clamp emitted scores to `[0,100]`
2. materialize missing universal adapter scores as `0`
3. compute the denominator from applicable adapters
4. compute the final MCP trust score as the weighted mean of adapter totals
