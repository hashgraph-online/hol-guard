# HOL-HCS-MCP-TRUST-DRAFT

## Scope

This local draft defines trust attribution for Codex plugin `.mcp.json` configuration.

## Goals

- explain how MCP trust is derived
- separate MCP trust from the broader plugin quality grade
- make transport and execution risk explicit instead of burying it in category points

## Adapters

### `verification` weight `1.0`

Internal component weights:

- `configIntegrity`: `40`
- `executionSafety`: `35`
- `transportSecurity`: `25`

Signal mapping:

- `configIntegrity`: `.mcp.json` parses and exposes expected top-level containers
- `executionSafety`: local MCP commands avoid dangerous execution patterns
- `transportSecurity`: remote MCP endpoints remain on HTTPS

### `metadata` weight `0.75`

Internal component weights:

- `serverNaming`: `25`
- `commandOrEndpoint`: `45`
- `configShape`: `30`

Signal mapping:

- `serverNaming`: MCP surfaces are explicitly named
- `commandOrEndpoint`: every MCP surface declares a concrete command or endpoint
- `configShape`: local arguments and remote entries follow the expected shape

## Normalization

The scanner emits a weighted adapter `score` plus component-level evidence, then normalizes the adapter total as the average of declared components. The final MCP trust score is the weighted average of adapter totals.
