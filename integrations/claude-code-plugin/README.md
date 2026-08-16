# HOL Guard for Claude Code

This directory is the Claude Code marketplace companion for [HOL Guard](https://github.com/hashgraph-online/hol-guard), the local-first security layer for AI agents.

The plugin intentionally does **not** duplicate Guard's runtime hook implementation. It gives Claude Code users a native marketplace discovery surface and guided setup/status skills; the installed `hol-guard` package remains the security authority and owns the Claude Code hooks, policy, approvals, and receipts.

## Install path

After this plugin is published to Anthropic's reviewed community marketplace:

```text
/plugin marketplace add anthropics/claude-plugins-community
/plugin install hol-guard@claude-community
```

Then run:

```text
/hol-guard:setup
```

The setup skill checks for the Guard CLI, asks before changing the machine, installs the documented PyPI package through `pipx` when approved, runs `hol-guard init`, and verifies status.

To check protection later without changing configuration:

```text
/hol-guard:status
```

## Security boundary

Installing this Claude plugin alone does not mean Guard is active. Runtime protection is active only when the local `hol-guard` installation reports the relevant Claude Code protection as healthy.

`hol-guard init` installs and maintains the actual Claude Code integration. Keeping that logic in the core project avoids two independently evolving hook implementations and preserves Guard's existing local approval and evidence behavior.

Guard Cloud is optional. Local Claude Code protection does not require a cloud account.

## Local validation

From the HOL Guard repository root:

```bash
claude plugin validate ./integrations/claude-code-plugin --strict
claude --plugin-dir ./integrations/claude-code-plugin
```

The marketplace submission should use the `integrations/claude-code-plugin` subdirectory from the HOL Guard repository. Anthropic's community catalog supports git subdirectory sources and pins approved plugins to a reviewed commit SHA.

## Adoption definition

These files are implementation support only. This work counts as external adoption only after Anthropic accepts the plugin into a public Claude marketplace or another external Claude ecosystem distribution surface makes it discoverable to users.
