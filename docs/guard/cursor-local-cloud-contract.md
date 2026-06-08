# Cursor Local Cloud Contract

Cursor support is split by surface so the dashboard does not imply protection the local harness cannot provide.

## Surfaces

| Surface | What Guard installs | What is intercepted |
| ------- | ------------------- | ----------------- |
| **Editor (IDE)** | MCP proxies in `.cursor/mcp.json` and native hooks in `.cursor/hooks.json` | Agent `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (Shell/MCP/Read), and `beforeReadFile` |
| **CLI** | `guard-cursor-agent` and `guard-cursor` shims on `PATH` | Launches routed through `hol-guard run cursor` before the real Cursor CLI agent starts |

Run `hol-guard apps connect cursor --surface all` (or `hol-guard install cursor` for both surfaces) to enable editor hooks and CLI shims.

### Cursor CLI entry points

Guard supports both modern Cursor CLI installs:

| User command | Guard shim | Resolved launch |
| ------------ | ---------- | --------------- |
| `cursor-agent ...` | `guard-cursor-agent ...` | `cursor-agent ...` when available |
| `cursor agent ...` | `guard-cursor agent ...` | `cursor agent ...` when the app CLI exposes the `agent` subcommand |

CLI install prepends `$HOL_GUARD_HOME/bin` to your shell profile when needed. Restart the shell or open a new terminal, then use the Guard shims instead of the raw Cursor binaries for preflight protection.

## Native Cursor hooks

Guard installs command hooks documented by Cursor:

- `beforeShellExecution` and `beforeMCPExecution` with `failClosed: true` so hook failures block risky actions
- `preToolUse` with matchers for Shell, MCP, Bash, and Read tools
- `beforeReadFile` for sensitive file reads before they reach the model

Hooks call a managed bridge script (`.cursor/hooks/hol-guard-cursor-hook.py`) that forwards stdin JSON to `hol-guard hook --harness cursor --json` and maps Guard policy results to Cursor `permission` responses (`allow`, `deny`, `ask`).

Restart Cursor after install so hook config reloads.

## Claude-compatible hooks inside Cursor

When Cursor loads Claude Code hooks (`.claude/settings.json` daemon URLs), Guard re-labels those events as harness `cursor` when `CURSOR_*` environment markers are present. Prefer `hol-guard install cursor` for first-class Cursor hook coverage; keep `hol-guard install claude-code` refreshed so daemon URLs include `runtime-harness=cursor` when both are used.

## Unsupported state

If a Cursor surface is unavailable or unsupported, Guard must say so directly and must not offer a no-op repair.

Unsupported Cursor states should:

- Explain which surface is unavailable.
- Keep any repair action disabled when Guard cannot change the local state.
- Direct the user to a supported Cursor editor or Cursor CLI setup path.

## Known blind spots

- Commands run in Cursor's **built-in terminal** outside the agent loop are not seen by agent hooks.
- `beforeTabFileRead` / Tab-only operations use a separate hook surface and are not installed by Guard today.
- Cloud agents load project `.cursor/hooks.json` but not user `~/.cursor/hooks.json`; use project-level install for cloud agent repos.
