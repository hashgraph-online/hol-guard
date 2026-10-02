# HOL Guard extension directory

HOL Guard 3 groups command protection into inspectable Extensions. Each Extension owns a stable capability boundary,
its rule metadata, safer alternatives, and the evidence it contributes to Guard's policy decision. Extensions detect
and explain command facts; they do not grant authority, execute commands, or replace Guard policy.

Use this directory to discover coverage shipped by the current source tree.
The tables are generated from the catalog compiled by Rust from canonical JSON
sources. `command explain`, the local dashboard, and catalog APIs read the same
generated metadata; the native program owns command matching. Directory checks
verify that the tables match that catalog.

To add or update coverage, start with the [contribution guide](contributing.md)
and [native source workflow](../extension-contributions.md). Edit
`contributions/command-sources/command.<name>.json`, add portable fixtures, and
regenerate the projections. New Python detector modules are not the contribution
path. The [Extension Builder](../extension-builder/README.md) can create a review
kit from an exported CLI inventory or MCP tool list.

```bash
# List every Extension.
hol-guard command extensions

# Inspect one Extension and its stable rules.
hol-guard command extensions command.git --json

# Test a command without executing it or creating an approval.
hol-guard command explain 'git reset --hard HEAD~1'
```

Protection model meanings:

- **Required core**: an immutable minimum protection floor shipped by HOL Guard.
- **Built in**: reviewed native coverage in the compiled catalog.
- **Package Firewall**: package operations delegated to Guard's supply-chain enforcement surface.
- **External opt-in**: a contributed extension that remains off until enabled through Guard's controls.

<!-- BEGIN GENERATED EXTENSION DIRECTORY -->

The current catalog is generated for each build and published in the CI run’s
`guard-extension-directory` output. The public directory consumes only successful
main builds. Contributors edit canonical sources and tests, not this inventory.

<!-- END GENERATED EXTENSION DIRECTORY -->

## Contribute

Start with the [Extension contribution guide](contributing.md). It covers proposal quality, stable identity design,
matcher constraints, safe-counterpart tests, privacy, validation, and the review rubric. New command coverage enters
the vetted built-in registry; Guard does not import executable detector code from workspaces or downloaded bundles.

For a large implementation, open a draft pull request with the **Command extension** template early so
maintainers can confirm scope and avoid overlapping IDs before the implementation is complete.

## Architecture and authority

- [Command Extension architecture](../command-extension-architecture.md)
- [Extension precedence and minimum actions](../command-extension-precedence.md)
- [Command Extension threat model](../command-extension-threat-model.md)
- [Local Extensions and protection settings](../managed-controls-local-extensions.md)
