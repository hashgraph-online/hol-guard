# Extension contributions

For exported command metadata or MCP tool inventories, start with the
[offline Extension Builder](extension-builder/README.md). It generates native
files and an integration plan while keeping every contribution External and off.
Semantic review and the activation requirements below still apply.

Community command-safety extensions are **external**. They stay off until a user turns them on for this device. HOL floors and HOL-curated libraries (AWS, Azure, Git, Kubernetes, Docker, and other mapped tools) stay on.

## Trust classes

- **first-party** — HOL floors. On by default. Required items cannot be turned off.
- **trusted-library** — HOL-curated protection for widely used tools. On by default.
- **external** — contributed tools. Listed as External. Off until you turn them on.

Turning off a first-party or trusted-library extension blocks that capability. Turning off an external extension returns it to inert: Guard does not apply that contribution, and first-party floors still apply.

## How to contribute

1. Add an in-tree detector module under `src/codex_plugin_scanner/guard/runtime/`.
2. Add a contribution file under `contributions/extensions/command.<name>.json`.
3. Add the id to the `external` list in `contracts/extensions/trust-class-map.v1.json`.
4. Do not put the id in `first-party` or `trusted-library`. Contribution files cannot self-declare those classes.

The schema is `contracts/extensions/contribution.v1.schema.json`. Required metadata: id, name, description, publisher, icon, executables, risk classes, action classes, and an in-tree `python-module` detector.

MCP servers use a parallel format under `contributions/mcp-servers/`. See [`mcp-server-contributions.md`](mcp-server-contributions.md).

Icons must use an allowlisted `react-icon` name or `kind: none`. Remote icon URLs are rejected.

## Review bar

- The detector must live in this repository. Guard does not download contribution code.
- New catalog ids must be added to the trust-class map in the same change. CI fails if a built-in id is missing.
- Custom device CLIs and unmapped local/test ids stay first-party. Only ids listed as `external` stay off until a local-admin enable.
- Tests must prove the contribution stays inert until a local-admin enable layer exists.
- A signed-cloud enable cannot turn an external contribution on. Local-admin enable is required.


## Native execution

Python modules are the reviewed authoring format, not hook-time plugins. The build
compiler turns every rule and safe variant into the packaged
`guard.native-command-program.v1` artifact. The Rust resident validates that
artifact once and evaluates the admitted matcher operations against its canonical
command model. Unknown matcher types fail compilation; a stale artifact fails CI.

After changing detector definitions or contribution metadata, run:

```sh
uv run python scripts/build_native_command_program.py
uv run python scripts/build_native_command_program.py --check
```

The authenticated policy snapshot binds the program, catalog, trust classes and
committed local/managed controls. External contributions still require local
opt-in. A control mutation closes the native authority fence before changing
stored settings, and a matching resident acknowledgement is required to reopen it.
Native receipts retain the program/control identity and a digest of bounded,
redacted observations. A missing or changed binding cannot reuse an older approval.

Package ecosystem entries retain their Package Firewall delegation. The native
command boundary applies their explicit disabled-permission gates without
claiming to replace package download, advisory or provenance scans. MCP entries
carry their packaged tool defaults into native PreToolUse; declared block rules
and explicit controls only strengthen the existing native result. Neither a
package name nor a server namespace grants allow authority. Unidentified MCPs
retain the native unknown/tool-review floor.

The installed-wheel gate exercises contribution opt-in, permission blocking,
safe-variant isolation, restart persistence, package/MCP controls, persisted
native receipts and tampered authority markers. The headless control fixture uses
generated production keys; interactive terminal enrollment is a separate flow.
