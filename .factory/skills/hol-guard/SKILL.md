---
name: hol-guard
description: Run HOL Guard scanner and guard operations via `uv run hol-guard`. Use when the user asks to scan plugins/MCP/skills for security, quality, or ecosystem compliance, or when they ask to run guard detect/install/protect workflows for local AI harnesses.
---

# HOL Guard

HOL Guard is an AI Antivirus scanner that checks plugins, MCP servers, skills, and local AI harnesses for security, quality, and ecosystem compliance.

## Prerequisites

- Always run from the `hol-guard` project root.
- Use `uv run hol-guard` to invoke the CLI. Never invoke Python modules directly.
- Ensure `uv sync --frozen --extra dev` has been run before invoking.

## Scanner Operations

Scan a plugin or skill directory:

```
uv run hol-guard scan <directory> [--format json|text|markdown|sarif] [--profile default|public-marketplace|strict-security] [--fail-on-severity critical|high|medium|low|info|none]
```

Lint rules:

```
uv run hol-guard lint <directory> [--list-rules] [--explain <rule-id>]
```

Verify runtime:

```
uv run hol-guard verify <directory> [--online]
```

List ecosystems:

```
uv run hol-guard --list-ecosystems
```

## Guard Operations

Detect harnesses:

```
uv run hol-guard detect [codex|claude|cursor|gemini|opencode] [--json]
```

Run guard in dry-run mode:

```
uv run hol-guard run <harness> --dry-run --default-action allow --json
```

Check guard status:

```
uv run hol-guard status [--json]
```

## Common Test Fixtures

Test fixtures live in `tests/fixtures/`:
- `good-plugin/` - clean Codex plugin with all required fields
- `bad-plugin/` - plugin with secrets, missing fields, bad practices
- `malicious-skill-plugin/` - skill with malicious patterns
- `multi-ecosystem-repo/` - repo with Codex, Claude, and Gemini configs
- `claude-plugin-good/` - clean Claude plugin
- `opencode-good/` - clean OpenCode plugin
- `gemini-extension-good/` - clean Gemini extension

## Verification

After each operation, verify:
- Exit code 0 for clean targets
- Exit code non-zero for targets with findings
- Output is valid JSON when `--format json` or `--json` is used
- Scanner reports findings with correct rule IDs and severities
