# Guard Get Started

Guard ships as the `hol-guard` package and command.
The scanner commands stay available in the same install for CI and package checks.

Use it when you want to protect a harness before local MCP servers, skills, hooks, or plugin surfaces run.

## The everyday flow

1. See what Guard found:

   ```bash
   hol-guard start
   ```

2. Install Guard in front of the harness you use most:

   ```bash
   hol-guard install codex
   ```

3. Run one dry pass so Guard records the current state:

   ```bash
   hol-guard run codex --dry-run
   ```

4. Launch through Guard after that. Guard will stop and ask if a tool is new or changed:

   ```bash
   hol-guard run codex
   ```

5. Review changes when Guard blocks or asks for another look:

   ```bash
   hol-guard diff codex
   hol-guard allow codex --scope artifact --artifact-id codex:project:workspace_skill
   hol-guard deny codex --scope artifact --artifact-id codex:project:workspace_skill
   ```

6. Check receipts and current status:

   ```bash
   hol-guard receipts
   hol-guard status
   ```

7. Sign in later only if you want shared history:

   ```bash
   hol-guard login --sync-url <url> --token <token>
   hol-guard sync
   ```

## What `install` does

`guard install <harness>` creates a local launcher shim under Guard’s home directory:

- macOS/Linux: `~/.config/.ai-plugin-scanner-guard/bin/guard-<harness>`
- Windows: `~/.config/.ai-plugin-scanner-guard/bin/guard-<harness>.cmd`

Claude Code also gets Guard hook entries in `.claude/settings.local.json` when you install from a workspace.

## First-party canaries

Use these local repos to prove Guard against real first-party surfaces:

- `hashnet-mcp-js` for a real MCP server harness target
- `registry-broker-skills` for a real skills registry fixture during scan and trust checks

Suggested local validation:

```bash
hol-guard detect codex --json
hol-guard install codex
hol-guard status
hol-guard run codex --dry-run
hol-guard receipts
```

For a real Codex canary, point `~/.codex/config.toml` or `<workspace>/.codex/config.toml` at a local `hashnet-mcp` command, then repeat the Guard loop above.
