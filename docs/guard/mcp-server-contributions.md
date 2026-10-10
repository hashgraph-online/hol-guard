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
2. Run `python scripts/refresh_extension_artifacts.py --trust-only`. It creates the missing `contracts/extensions/trust/command.mcp-<name>.v1.json` binding as external/opt-in without changing existing classifications. Include that per-extension file in the PR; there is no shared trust list to edit. Run the read-only `python scripts/refresh_extension_artifacts.py --check-trust` to verify ownership before building.
3. Package the JSON through Hatch force-include. The packaged-contract copy script enumerates `contributions/mcp-servers/` automatically, so no script edit is required. The Builder's reviewed `apply` plan handles any remaining integration edits for generated kits.
4. Submit the authored MCP input, its trust binding, and the packaging integration edits in step 3 together. Do not commit generated catalogs or directory files. Required CI checks authored trust before preparation can create defaults in its scratch checkout. CI then prepares and verifies projections, and maintainer artifact regeneration publishes shared outputs after merge.
5. Run `tests/test_guard_mcp_server_contribution.py` and the trust checks using the [validation workflow](extension-builder/VALIDATION.md#source-tree-checks).

Do not declare `trusted-library` or `first-party`. The schema only allows `external`.

The schema is `contracts/mcp-servers/contribution.v1.schema.json`. Required metadata: id, name, description, publisher, icon, launch identity, risk classes, and tool defaults.

Package-launched contributions use `launch.kind: package-launcher`, an allowlisted
package command, and a package name. Package-name matching selects tightening
`review` and `block` defaults without requiring the full argument hash. An `allow`
default additionally requires a stdio server identity using the declared launcher
(including its portable executable path or wrapper suffix), an explicit `default`
package-source token, a registry version/range/tag selector, and a recorded
environment-key list. Unversioned registry packages are supported. Aliases, Git
or file selectors, archive basenames, and configured package-manager environment
variables cannot receive contributed `allow` defaults. This includes case-insensitive
`npm_config_*`, `YARN_*`, `UV_*`, `PIP_*`, `PIPX_*`, and scoped `*:registry` keys:
configuration-file overrides can redirect sources without an argv registry flag.
Different launchers, explicit registry/index overrides, and missing or malformed
launch identity fields also retain host policy for allow decisions. Native source
classification includes `--userconfig`, `--globalconfig`, scoped registry options,
configuration-file and index options, and forwarded pip arguments. Unrecognized
options before the package also retain host policy; npm options remain launcher
options until `--`. Newly recognized source/configuration values and unrecognized
argv are bound by digests without exposing their contents. Existing explicit
registry/index tokens retain their format. User paths, registry package versions/tags,
ordinary server environment, recognized neutral launcher switches such as `-y`,
and server arguments can still vary. Exact command, argument, and environment
hashes continue to bind saved approvals.

These source checks follow the distinction between registry names and
[aliases, folders, tarballs, and Git selectors](https://docs.npmjs.com/cli/v11/using-npm/package-spec/).
The native `default` source token describes argv flags; it does not attest to the
installed code or the effective contents of package-manager configuration files.

Native servers installed through Homebrew, Cargo, or release archives may use
`launch: {"kind": "direct-command", "command": "example-mcp"}`. The command is a
lowercase ASCII executable basename (letters, digits, hyphens, underscores and
nonempty dot-separated components; at most 128 characters), without a path or
wrapper suffix. Generic shells, interpreters, package launchers, and runtime
wrappers such as `sh`, `node`, `python`, `npx`, `docker`, and `uv` are reserved
and cannot be claimed. A single contribution owns each command. The MCP identity
matcher accepts POSIX and Windows paths, case-folds the executable basename, and
strips a trailing `.exe`, `.cmd`, or `.bat` before matching. It requires stdio and
a tool identity and never infers the target from shell arguments. Package
identities and remote transports do not match this launch kind.

Direct-command defaults apply to every stdio MCP invocation of that basename;
arguments are deliberately not part of catalog selection, so repository paths
and user flags can vary. Argument-specific policies and shell/interpreter wrappers
are not supported by this variant. The complete command and argument hashes still
bind saved approvals. Basename recognition is not executable authentication:
direct-command contributions can only `inherit`, `review`, or `block`, never
`allow`. Normal launch identity checks and stronger floors still apply.

Native delegated controls retain their existing tightening-only MCP namespace
matching (`mcp__<contribution-suffix>__<tool>`); they do not infer an MCP server
from a shell segment or package name. The identity-aware MCP contribution path
uses the configured stdio executable even when the server is given another name.

Hosted MCP servers may use `launch.kind: remote-http` with the official HTTPS endpoint and one or more canonical configured server names. When Guard has exact runtime endpoint evidence, the endpoint must match. Query parameters are excluded from endpoint matching and from serialized server identity metadata, so query credentials are not emitted in Guard artifacts. Some harnesses expose only the configured server name and transport; that fallback is permitted only when no endpoint identity is available. A mismatched, malformed, or unrecognized remote endpoint stays on Guard's normal handling.

Icons must use an allowlisted `react-icon` name or `kind: none`. Remote icon URLs are rejected. There is no downloaded detector and no Python matcher for v1 contribution metadata.

## Tool defaults

Each package-launched tool is `inherit`, `allow`, `review`, or `block`. Remote HTTP and direct-command contributions are limited to `inherit`, `review`, or `block`. Missing tools use the `other` row, then inherit Guard's usual handling. `allow` never overrides an existing block or sandbox-required floor. `review` can strengthen an otherwise allowed or warning-level tool call, but it cannot weaken a stronger requirement.

Evaluation order for a live `tools/call` is:

1. Temporary browser MCP grant
2. This-device custom MCP grant
3. Contributed defaults when the catalog item is locally enabled
4. First-party floors and stronger policy requirements

v1 enables the whole contributed server entry. Per-tool catalog permissions are out of scope.

## Review bar

- New catalog ids must have a committed external/opt-in binding. The helper creates missing bindings conservatively; CI rejects absent bindings before preparation. Changes to existing reviewed trust classes still require review.
- Tests must prove the contribution stays inert until a local-admin enable exists.
- A this-device custom MCP grant must still win over the contribution.
- Remote HTTP contributions must prove they cannot lower policy through an `allow` state.
- Cloud `guard.extension-catalog.v1` keys stay unchanged. New catalog items may change the digest.
