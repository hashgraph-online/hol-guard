# PRD: v2 Codex Spec Alignment and Runtime Hardening

## Summary

`codex-plugin-scanner` should become the default readiness gate for Codex plugins by aligning its validation and verification logic to the current Codex plugin and marketplace conventions, hardening MCP runtime verification, and reducing GitHub Action adoption friction.

This release is intentionally scoped to the highest-confidence gaps identified in [code-scanner-research.md](/Users/michaelkantor/CascadeProjects/hashgraph-online/code-scanner-research.md):

- first-class support for Codex repo marketplaces at `.agents/plugins/marketplace.json`
- path semantics that preserve documented `./`-prefixed relative paths instead of stripping them
- manifest validation that stops requiring undocumented `interface.type`
- MCP stdio verification that performs a lifecycle-compliant initialize flow
- GitHub Action ergonomics for SARIF upload and policy/verification outputs

## Problem

The scanner already has strong policy, scoring, suppression, and CI foundations, but it still diverges from the current Codex packaging contract in a few critical ways:

- marketplace validation assumes a legacy root `marketplace.json` shape instead of the Codex repo marketplace path and schema
- safe autofix rewrites documented `./` path prefixes away
- runtime MCP verification sends an empty `initialize` payload and does not send `notifications/initialized`
- Action adoption still requires manual SARIF wiring even though SARIF is a first-class output

Those gaps create false negatives, false positives, and trust issues for plugin authors who are following the docs correctly.

## Goals

- Validate Codex marketplaces at `.agents/plugins/marketplace.json` using the documented `plugins[].source.path` object shape.
- Keep legacy root `marketplace.json` support only as a compatibility fallback with an explicit deprecation signal.
- Preserve and autofix documented `./`-prefixed relative paths for manifest and marketplace references.
- Perform a protocol-grade MCP stdio initialize flow and capture richer traces for `doctor`.
- Let plugin authors opt into SARIF upload directly from the scanner Action with least-privilege guidance.

## Non-goals

- Replacing `$plugin-creator`
- Adding network-on-by-default verification
- Reworking the existing score model or registry artifact schemas beyond what is required for this spec-alignment release
- Building a generic MCP remote inspector beyond safe reachability and stdio lifecycle verification

## Users

- Codex plugin authors shipping repository-local plugins
- Teams maintaining repo-local marketplaces of plugins
- Registry maintainers consuming scanner artifacts and SARIF

## Scope

### 1. Marketplace spec alignment

- Default marketplace location becomes `.agents/plugins/marketplace.json`.
- Validation accepts:
  - `name: string`
  - optional `interface.displayName`
  - `plugins: []`
  - each plugin entry with:
    - `source: { source: string, path: string }`
    - `policy.installation`
    - `policy.authentication`
    - `category`
- `source.path` must:
  - start with `./`
  - resolve inside the marketplace root
- legacy root `marketplace.json` remains supported in v2 with a compatibility warning path in validation/verification/docs.

### 2. Manifest and path semantics

- `interface.type` is no longer required for publishability.
- interface asset paths and manifest-declared local paths must preserve `./` prefixes where Codex expects them.
- autofix upgrades eligible local paths to documented `./` form instead of stripping prefixes.

### 3. MCP verification hardening

- stdio MCP verification sends:
  - `initialize` with `protocolVersion`, `capabilities`, and `clientInfo`
  - `notifications/initialized`
  - optional capability probes for `tools/list`, `resources/list`, and `prompts/list` when declared by the server
- traces recorded for `doctor` include the full request/response sequence and timeout classification.

### 4. Action ergonomics

- composite Action adds optional SARIF upload support:
  - `upload_sarif`
  - `sarif_category`
- Action outputs explicitly include `policy_pass` and `verify_pass`.
- docs provide the required `security-events: write` guidance for SARIF upload.

## Acceptance criteria

- A plugin repo with `.agents/plugins/marketplace.json` and `./`-prefixed `source.path` passes marketplace checks.
- `lint --fix` never strips a valid `./` prefix from manifest or marketplace paths.
- a manifest with a publishable `interface` object but no `interface.type` passes interface metadata checks.
- MCP stdio verification records a successful initialize + initialized exchange against a compliant stub server.
- `doctor --bundle` contains real stdio trace output for the MCP lifecycle exchange.
- the GitHub Action can scan in SARIF mode and optionally upload the generated SARIF when permissions are present.

## Verification plan

- unit tests for marketplace parsing, path normalization, manifest interface metadata, MCP lifecycle traces, and Action runner outputs
- CLI tests covering `lint --fix`, `verify`, and `doctor --bundle`
- targeted Action tests for `upload_sarif`, `policy_pass`, and `verify_pass`
- full `pytest`, `ruff check`, `ruff format --check`, and `python -m build`
