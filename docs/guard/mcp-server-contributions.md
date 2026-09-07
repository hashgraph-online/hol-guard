# MCP server contributions

For exported command metadata or MCP tool inventories, start with the
[offline Extension Builder](extension-builder/README.md). It generates native
files and an integration plan while keeping every contribution External and off.
Semantic review and the activation requirements below still apply.

Community MCP servers can ship in the Guard catalog the same way command-safety extensions do: a reviewed JSON file, an External badge, and **off until you turn it on**.

Operators can still add an unlisted MCP server with **Add custom extension**. Custom this-device grants override contributed defaults.

## Trust

- Contributed MCP servers are **external** and **opt-in**.
- HOL floors and HOL-curated libraries stay on.
- A signed-cloud enable cannot turn a contributed MCP server on. Local-admin enable is required.
- Turning a contributed MCP server off returns it to inert. First-party MCP floors still apply.

## How to contribute

1. Add `contributions/mcp-servers/mcp.<name>.json`.
2. Add catalog id `command.mcp-<name>` to the `external` list in `contracts/extensions/trust-class-map.v1.json`.
3. Package the JSON through Hatch force-include and the packaged-contract copy script.
4. Do not declare `trusted-library` or `first-party`. The schema only allows `external`.

The schema is `contracts/mcp-servers/contribution.v1.schema.json`. Required metadata: id, name, description, publisher, icon, package launcher, risk classes, and tool defaults.

Launch matching uses the MCP package name, not the full argument hash, so user paths and extra flags still match. Icons must use an allowlisted `react-icon` name or `kind: none`. Remote icon URLs are rejected. There is no downloaded detector and no Python matcher for v1.

## Tool defaults

Each tool is `inherit`, `allow`, or `block`. Missing tools use the `other` row, then inherit Guard's usual review. `allow` never overrides an existing block or sandbox-required floor.

Evaluation order for a live `tools/call` that is already on review / require-reapproval / warn:

1. Temporary browser MCP grant
2. This-device custom MCP grant
3. Contributed defaults when the catalog item is locally enabled
4. First-party floors

v1 enables the whole server. Per-tool catalog permissions are out of scope.

## Review bar

- New catalog ids must be added to the trust-class map in the same change.
- Tests must prove the contribution stays inert until a local-admin enable exists.
- A this-device custom MCP grant must still win over the contribution.
- Cloud `guard.extension-catalog.v1` keys stay unchanged. New catalog items may change the digest.
