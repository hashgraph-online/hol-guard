# Guard Get Started

Install `hol-guard` when you want local harness protection.
Install `plugin-scanner` separately when you want maintainer or CI checks for plugin packages.

Use it when you want to protect a harness before local MCP servers, skills, hooks, or plugin surfaces run.

## The everyday flow

1. See what Guard found:

   ```bash
   hol-guard bootstrap
   ```

2. If you prefer the manual path, install Guard in front of the harness you use most:

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

5. If the shell is interactive, approve inline. If the shell cannot prompt, Guard queues the change in the local approval center instead of ending the session with a dead stop:

   ```bash
   hol-guard approvals
   ```

6. Review or resolve changes from the terminal when you want a text-only path:

   ```bash
   hol-guard approvals approve <request-id>
   hol-guard approvals deny <request-id>
   hol-guard diff codex
   ```

7. Check receipts and current status:

   ```bash
   hol-guard receipts
   hol-guard status
   ```

8. Sign in later only if you want shared history:

   ```bash
   hol-guard login --sync-url <url> --token <token>
   hol-guard sync
   ```

## Fine-tune local policy

Guard works with local defaults first, then optional overrides for a harness, publisher, or artifact.

Home config:

```toml
mode = "prompt"
default_action = "warn"
changed_hash_action = "require-reapproval"

[harnesses.codex]
default_action = "allow"

[publishers.hashgraph-online]
default_action = "allow"

[artifacts."codex:project:workspace_tools"]
default_action = "sandbox-required"
```

Optional project override:

```toml
# .ai-plugin-scanner-guard.toml
[artifacts."codex:project:workspace_tools"]
default_action = "block"
```

Guard resolves decisions in this order:

1. saved decisions from `hol-guard allow` or `hol-guard deny`
2. project override file
3. home config
4. Guard's built-in recommendation

Use these actions in config or saved decisions:

- `allow`
- `warn`
- `block`
- `sandbox-required`
- `require-reapproval`

## What `install` does

`guard install <harness>` creates a local launcher shim under Guard’s home directory:

- macOS/Linux: `~/.config/.ai-plugin-scanner-guard/bin/guard-<harness>`
- Windows: `~/.config/.ai-plugin-scanner-guard/bin/guard-<harness>.cmd`

Claude Code also gets Guard hook entries in `.claude/settings.local.json` when you install from a workspace.

Copilot CLI gets a Guard-owned repo hook file at `.github/hooks/hol-guard-copilot.json` when you install from a workspace. Guard only reads `~/.copilot/config.json` and `~/.copilot/mcp-config.json`; it does not auto-write user-level Copilot config.

## Harness approval model

Guard uses three approval tiers:

1. native harness approval where the harness already has a strong tool permission model
2. the local Guard approval center on `127.0.0.1` when Guard needs to pause a launch cleanly
3. terminal resolution through `hol-guard approvals` when you do not want a browser surface

Current strategy:

- `claude-code`
  prefers Claude hooks and can hand blocked work to the approval center cleanly
- `copilot`
  wraps the `copilot` CLI, watches documented repo hooks and MCP config, and treats workspace `.vscode/mcp.json` as MCP artifact detection only
- `codex`
  uses the Guard approval center today; App Server is the long-term richer in-client path
- `cursor`
  keeps Cursor’s native tool approval and lets Guard own artifact trust before tool use
- `opencode`
  keeps OpenCode’s permission model and lets Guard manage package and provenance policy
- `gemini`
  scans extension manifests and routes blocked changes to the approval center

Guard does not claim VS Code Copilot extension-host interception in this pass, and it does not add Cisco AIBOM runtime policy logic. AIBOM can come back later only as evidence or export.

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
