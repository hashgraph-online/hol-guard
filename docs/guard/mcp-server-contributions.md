# MCP server contributions

For exported command metadata or MCP tool inventories, start with the
[offline Extension Builder](extension-builder/README.md). It generates native
files and an integration plan while keeping every contribution External and off.
Semantic review and the activation requirements below still apply.

MCP contributions keep their existing JSON contract in `contributions/mcp-servers/`.
The Rust source compiler lowers these files into the native catalog alongside
command sources. The [command source format](extension-contributions.md) is a
separate input for CLI coverage; MCP authors do not need to create a Python
detector or rewrite a server contribution as a command source.

Community MCP servers can ship in the Guard catalog the same way command-safety extensions do: a reviewed JSON file, an External badge, and **off until you turn it on**.

Operators can still add an unlisted MCP server with **Add custom extension**. Custom this-device grants override contributed defaults.

## Trust

- Contributed MCP servers are **external** and **opt-in**.
- HOL floors and HOL-curated libraries stay on.
- A signed-cloud enable cannot turn a contributed MCP server on. Local-admin enable is required.
- Turning a contributed MCP server off returns it to inert. First-party MCP floors still apply.
- Remote HTTP contributions can strengthen a tool to `review` or `block`; they cannot declare an `allow` default because a configured remote server name is not sufficient authority to weaken Guard policy.

## How to contribute

1. Add `contributions/mcp-servers/mcp.<name>.json`.
2. New catalog ids default to `external` and opt-in. Extension builder CI stages missing entries in the shared trust map before building; contributors do not need to edit that shared list.
3. Package the JSON through Hatch force-include and the packaged-contract copy script. The Builder's reviewed `apply` plan handles these integration edits for generated kits.
4. Submit the authored MCP input and tests together with the packaging integration edits in step 3. In particular, the frozen-build copy list must include the new MCP JSON; source-only trust preparation does not replace that packaging integration. Do not commit generated catalogs or directory files. CI prepares and verifies projections on the PR merge checkout, and maintainer artifact regeneration publishes shared outputs after merge.
5. Run `tests/test_guard_mcp_server_contribution.py`, the trust checks, and any generated MCP test file using the [validation workflow](extension-builder/VALIDATION.md#source-tree-checks).

Do not declare `trusted-library` or `first-party`. The schema only allows `external`.

The schema is `contracts/mcp-servers/contribution.v1.schema.json`. Required metadata: id, name, description, publisher, icon, launch identity, risk classes, and tool defaults.

Package-launched contributions use `launch.kind: package-launcher`, an allowlisted package command, and a package name. Launch matching uses the MCP package name, not the full argument hash, so user paths and extra flags still match.

Hosted MCP servers may use `launch.kind: remote-http` with the official HTTPS endpoint and one or more canonical configured server names. When Guard has exact runtime endpoint evidence, the endpoint must match. Query parameters are excluded from endpoint matching and from serialized server identity metadata, so query credentials are not emitted in Guard artifacts. Some harnesses expose only the configured server name and transport; that fallback is permitted only when no endpoint identity is available. A mismatched, malformed, or unrecognized remote endpoint stays on Guard's normal handling.

Icons must use an allowlisted `react-icon` name or `kind: none`. Remote icon URLs are rejected. There is no downloaded detector and no Python matcher for v1 contribution metadata.

## Tool defaults

Each package-launched tool is `inherit`, `allow`, `review`, or `block`. Remote HTTP contributions are limited to `inherit`, `review`, or `block`. Missing tools use the `other` row, then inherit Guard's usual handling. `allow` never overrides an existing block or sandbox-required floor. `review` can strengthen an otherwise allowed or warning-level tool call, but it cannot weaken a stronger requirement.

Evaluation order for a live `tools/call` is:

1. Temporary browser MCP grant
2. This-device custom MCP grant
3. Contributed defaults when the catalog item is locally enabled
4. First-party floors and stronger policy requirements

v1 enables the whole contributed server entry. Per-tool catalog permissions are out of scope.

## Review bar

- New catalog ids must resolve to external/opt-in. CI and maintainer regeneration add missing ids conservatively; changes to existing reviewed trust classes still require review.
- Tests must prove the contribution stays inert until a local-admin enable exists.
- A this-device custom MCP grant must still win over the contribution.
- Remote HTTP contributions must prove they cannot lower policy through an `allow` state.
- Cloud `guard.extension-catalog.v1` keys stay unchanged. New catalog items may change the digest.
