# Guard Get Started

Install `hol-guard` when you want local harness protection.
Install `plugin-scanner` separately when you want maintainer or CI checks for plugin packages.

Use it when you want to protect a harness before local MCP servers, skills, hooks, or plugin surfaces run.

## The everyday flow

1. See what Guard found:

   ```bash
   hol-guard bootstrap
   ```

   For a Hermes-first setup:

   ```bash
   hol-guard hermes bootstrap
   ```

2. If you prefer the manual path, install Guard in front of the harness you use most:

   ```bash
   hol-guard install codex
   ```

   After upgrading later, run `hol-guard update` to update the installed `hol-guard` package in that environment.

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

8. Connect cloud sync later only if you want shared history:

   ```bash
   hol-guard connect
   ```

9. Inspect or rotate the local installation identity that cloud sync uses:

   ```bash
   hol-guard device show
   hol-guard device label set "VPS - Hermes runtime"
   hol-guard device rotate
   ```

## Evidence-first decisions

Guard now scores local decisions from structured evidence, not only string heuristics. Each changed artifact carries:

- typed risk signals with confidence and remediation
- capability deltas like `new_network_host`, `secret_scope_expanded`, and `subprocess_added`
- provenance state and local history context
- review priority and suppressibility guidance

Runtime prompt intent is also evaluated as first-class risk input. Guard detects more than direct `.env` reads, including:

- secret-bearing files (`~/.ssh`, `~/.aws/credentials`, `~/.kube/config`, `.npmrc`, `.pypirc`, Docker auth config)
- exfil-like intent (`upload`, `post`, `webhook`, `gist`, transfer verbs)
- subprocess and shell-wrapper expansion
- destructive mutation intent
- Guard bypass intent

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
# .hol-guard.toml
[artifacts."codex:project:workspace_tools"]
default_action = "block"
```

Guard still reads the legacy `.ai-plugin-scanner-guard.toml` file if you already have one, but new local overrides should use `.hol-guard.toml`.

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

- macOS/Linux: `~/.hol-guard/bin/guard-<harness>`
- Windows: `~/.hol-guard/bin/guard-<harness>.cmd`

Claude Code also gets Guard hook entries in `.claude/settings.local.json` when you install from a workspace.

Copilot CLI gets a Guard-owned repo hook file at `.github/hooks/hol-guard-copilot.json` when you install from a workspace. Guard only reads `~/.copilot/config.json` and `~/.copilot/mcp-config.json`; it does not auto-write user-level Copilot config.

OpenCode gets the normal Guard shim plus a Guard-owned runtime overlay at `<guard-home>/opencode/runtime-config.json`. Guard
injects that overlay through `OPENCODE_CONFIG_CONTENT` when you launch through Guard so native skill loads stay on ask
without mutating your checked-in `opencode.json`.

Hermes gets the normal Guard shim plus a Guard-owned bundle at `<guard-home>/hermes/` with:

- `mcp-overlay.json`
- `pretool-hook.json`
- `manifest.json`

Guard injects the managed overlay paths through `HERMES_GUARD_MCP_OVERLAY_PATH` and `HERMES_GUARD_PRETOOL_PATH` when
you launch Hermes through Guard.

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
  uses inline MCP elicitation in the same Codex chat when the interactive CLI or Codex App can answer it, and falls back to the local Guard approval center for `codex exec` or any other nonresponsive session
- `cursor`
  keeps Cursor’s native tool approval and lets Guard own artifact trust before tool use
- `antigravity`
  scans Antigravity settings, installed extensions, and Antigravity-owned MCP or skill roots before launch
- `opencode`
  detects OpenCode MCP servers, commands, plugins, and skills before launch, and `guard install opencode` adds a
  Guard-owned runtime overlay that keeps native skill loads on ask
- `hermes`
  prefers the managed Hermes same-channel path when Guard owns the overlay bundle, falls back to the approval center,
  and keeps browser auto-open off for blocked requests
- `gemini`
  scans `.gemini/settings.json`, extension manifests, hooks, MCP registrations, and Gemini skill directories before
  launch, then routes blocked changes to the approval center

Guard does not claim VS Code Copilot extension-host interception in this pass. A VS Code inline tool prompt by itself is
not proof that Guard blocked the action, because that prompt can come from VS Code's own permission surface. For Copilot,
count Guard proof only from CLI hook responses, Guard runtime receipts, or an MCP client that explicitly answers Guard
elicitation. Guard also does not add Cisco AIBOM runtime policy logic in this pass. AIBOM can come back later only as
evidence or export.

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

## Codex-specific approval behavior

Guard now has two real runtime paths for Codex MCP tool calls:

1. interactive Codex CLI and Codex App
   Guard sends an MCP `elicitation/create` approval request, so the user can approve or deny in the same Codex chat
2. noninteractive Codex runs such as `codex exec`
   if Codex does not answer the elicitation request, Guard queues a localhost approval request and returns the request id plus approval URL in the same tool-call error

That means the user should never get a silent pass-through on a risky MCP tool call:

- same-chat approve or deny when Codex can render the inline prompt
- explicit approval-center recovery when the session cannot
