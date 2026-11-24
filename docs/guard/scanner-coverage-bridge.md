# Scanner coverage context

The scanner can show a contextual Guard coverage section when a package contains
a runtime-bearing surface. The section is a report-only bridge between scanner
findings and the Guard harness claims in [`harness-claims.md`](harness-claims.md).

## What it reports

- The package surfaces detected by the scanner, such as prompts, MCP servers,
  hooks, or command modules.
- The matching Guard harness and its declared event claims for those surfaces.
- Links to the coverage matrix and the local installation guide.
- A boundary statement that separates static package analysis from runtime
  protection.

The bridge reads the checked-in
`harness-protection-contracts.v1.json` contract. It does not inspect the local
host, install Guard, execute package code, or make a network request. A
`configured` claim means Guard declares that boundary in its contract. It does
not prove that a user installed Guard, that a host version is supported, or that
a live action was blocked.

## JSON shape

JSON reports add an optional `guardCoverage` object only when a mapped runtime
surface is present. Its schema is `guard-coverage-bridge.v1` and includes
`detectedSurfaces`, the matching `harnesses`, and the `boundary` statement.
The object contains no source content, findings text, secrets, environment
values, or local paths.

For a release workflow that turns this context into attested evidence, see
[Scanner to release evidence starter](scanner-to-release-starter.md).
