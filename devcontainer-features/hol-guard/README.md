# HOL Guard DevContainer Feature

Installs [HOL Guard](https://hol.org/guard) into your dev container — local-first security for AI coding agents.

## Quick Start

Add this to your `devcontainer.json`:

```json
{
    "image": "mcr.microsoft.com/devcontainers/python:3.12",
    "features": {
        "ghcr.io/hashgraph-online/hol-guard/hol-guard:1": {}
    }
}
```

That's it. HOL Guard installs automatically on container build.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `version` | string | `latest` | HOL Guard version (`latest` or specific like `2.0.1004`) |
| `initHarness` | string | `auto` | `auto` (detect installed harnesses), `none` (skip init), or a specific name (`codex`, `claude-code`, `cursor`, `gemini`, `opencode`, `pi`) — informational only, Guard auto-detects regardless |
| `strictMode` | boolean | `false` | Enable strict mode (blocks untrusted tool actions by default) |

## Example: Cursor + Strict Mode

```json
{
    "features": {
        "ghcr.io/hashgraph-online/hol-guard/hol-guard:1": {
            "version": "latest",
            "initHarness": "cursor",
            "strictMode": true
        }
    }
}
```

## What is HOL Guard?

HOL Guard intercepts tool actions before files change or networks are contacted. It protects AI coding agents (Codex, Claude Code, Cursor, Gemini, OpenCode, Pi) from supply-chain attacks in plugins and MCP servers.

- [Documentation](https://hol.org/guard)
- [GitHub](https://github.com/hashgraph-online/hol-guard)
- [PyPI](https://pypi.org/project/hol-guard/)
