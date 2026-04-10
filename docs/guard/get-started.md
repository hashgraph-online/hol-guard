# Guard Get Started

Guard is the local product inside `plugin-scanner`.
If you want the shortest entrypoint, install and run the dedicated `plugin-guard` console script.

Use it when you want to protect a harness before local MCP servers, skills, hooks, or plugin surfaces run.

## The local loop

1. Detect your harnesses:

   ```bash
   plugin-guard guard start
   ```

2. Install Guard in front of the harness you use most:

   ```bash
   plugin-guard guard install codex
   ```

3. Run one dry pass so Guard records the current state:

   ```bash
   plugin-guard guard run codex --dry-run
   ```

4. Launch through Guard after that. Guard will prompt you if a tool is new or changed:

   ```bash
   plugin-guard guard run codex
   ```

5. Review changes when Guard blocks or asks for another look:

   ```bash
   plugin-scanner guard diff codex
   plugin-scanner guard allow codex --scope artifact --artifact-id codex:project:workspace_skill
   plugin-scanner guard deny codex --scope artifact --artifact-id codex:project:workspace_skill
   ```

6. Inspect receipts:

   ```bash
   plugin-guard guard receipts
   plugin-guard guard status
   ```

7. Connect sync only if you want shared history later:

   ```bash
   plugin-scanner guard login --sync-url <url> --token <token>
   plugin-scanner guard sync
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
plugin-scanner guard detect codex --json
plugin-scanner guard install codex
plugin-scanner guard status
plugin-scanner guard run codex --dry-run
plugin-scanner guard receipts
```

For a real Codex canary, point `~/.codex/config.toml` or `<workspace>/.codex/config.toml` at a local `hashnet-mcp` command, then repeat the Guard loop above.
