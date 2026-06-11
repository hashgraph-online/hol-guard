# Harness Support Matrix

Local harness protection works without signing in to Guard Cloud. Cloud adds synced
history, visibility, and team controls around the same adapters. See
[Local Guard vs Guard Cloud](./local-vs-cloud.md).

Current Guard support in this repo:

- `codex`
  - detects global and project `config.toml`
  - detects Guard-managed `.codex/hooks.json` Bash hook entries
  - parses configured MCP servers
  - installs Guard-owned Codex `PreToolUse` Bash hooks so native shell commands can be denied before execution even when Codex itself is running in YOLO mode
  - serializes package-manager shell intent, package metadata, and the final pre-execution Guard result into the shared runtime envelope before Guard queues or blocks the action
  - supports wrapper-mode `guard run codex`
  - wrapper prompt screening now suppresses copied debug and incident context while still escalating risky prompt intent
  - uses same-chat MCP elicitation for live managed MCP tool approvals in the interactive CLI and Codex App
  - falls back to the local approval center only for nonresponsive or headless Codex sessions such as `codex exec`
  - when a browser approval request has a live Codex thread binding, approving or blocking in the browser resumes that same Codex thread with HOL Guard continuation copy and the exact blocked command context
  - headless Codex sessions resume through `codex exec resume` with Guard-managed hooks still enabled, so saved approvals can replay the blocked command instead of forcing a manual retry
  - when no Codex thread binding is available, returns an explicit manual fallback instead of a false resume success
- `claude-code`
  - detects global and project settings, hooks, `.mcp.json`, and workspace agents
  - supports local hook install and uninstall in `.claude/settings.local.json`
  - has native `UserPromptSubmit` and `PreToolUse` Guard hook coverage
  - carries package-manager shell intent and pre-execution block state through the shared Guard runtime envelope before Claude sees the denied tool response
  - is the best current harness for graceful approval deferral
- `copilot`
  - detects read-only user config in `~/.copilot/config.json` and `~/.copilot/mcp-config.json`
  - detects workspace `.vscode/mcp.json` as documented MCP artifact input only
  - detects repo-local Copilot CLI hooks from `.github/hooks/*.json`
  - installs and removes Guard-owned repo hooks in `.github/hooks/hol-guard-copilot.json`
  - supports wrapper-mode `guard run copilot`
  - has native `userPromptSubmitted`, `preToolUse`, and `postToolUse` hook coverage normalized onto the shared Guard runtime
  - package-manager shell tool calls now persist package intent, consistent block copy, and pre-execution Guard state before Copilot retries
- `cursor`
  - detects global and project `mcp.json`
  - installs native Cursor hooks in `.cursor/hooks.json` for `beforeShellExecution`, `beforeMCPExecution`, `preToolUse`, and `beforeReadFile`
  - supports wrapper-mode management state and `guard-cursor-agent` / `guard-cursor` CLI shims
  - wrapper prompt screening is covered for benign debug prompts and risky secret-read prompts
  - leaves native Cursor tool approval in place for `ask` decisions and focuses Guard on artifact trust plus runtime interception
  - managed MCP package-manager tool calls are routed through the supply-chain decision engine before Cursor receives the tool result
  - uses the Cursor local/cloud contract in [cursor-local-cloud-contract.md](cursor-local-cloud-contract.md) to keep editor and CLI status, repair, receipts, and Cloud sync distinct under one Cursor app
- `antigravity`
  - detects Antigravity user settings, installed extension profiles, and Antigravity-owned MCP and skill roots
  - supports wrapper-mode management state
  - uses the local approval center for blocked artifact changes today
- `gemini`
  - detects `.gemini/settings.json`, local extension manifests, embedded MCP declarations, hooks, and Gemini skill directories
  - supports wrapper-mode management state
  - wrapper prompt screening is covered for benign debug prompts and risky secret-read prompts
  - falls back to the local approval center when Guard blocks a launch
  - native package-manager shell actions now use the same package intent contract, consistent block copy, and evidence payload as the other managed harnesses
- `hermes`
  - detects Hermes skills plus MCP servers from `~/.hermes/config.yaml` and `~/.hermes/mcp_servers.json`
  - supports `hol-guard hermes bootstrap` and a Guard-managed Hermes overlay bundle under Guard home
  - rewrites managed Hermes MCP entries through Guard’s existing proxy path and uses native-or-center delivery when the managed bundle is present
  - blocks sensitive file reads and Docker-sensitive native pre-tool actions through the existing Guard hook path
  - package-manager shell actions now emit shared package intent metadata and use the same pre-execution package block flow as Codex, Claude Code, Gemini, Copilot, and OpenCode
- `openclaw`
  - detects `~/.openclaw/openclaw.json`, gateway posture, channels, MCP servers, workspace skills, user skills, and OpenClaw-owned skills
  - supports a Guard-managed OpenClaw overlay bundle under Guard home without mutating user OpenClaw config
  - flags open DM channel posture and remote MCP endpoints before launch so chat-originated agent work can be reviewed
  - uses native-or-center delivery when the managed bundle is present and keeps browser auto-open off for blocked requests
  - managed MCP package-manager calls now route through the supply-chain package evaluator before OpenClaw receives the tool result
- `opencode`
  - detects global and project config, MCP servers, config-defined commands, markdown commands, npm plugins, local
    plugin files, and OpenCode-compatible skill directories
  - installs a Guard-owned pretool plugin in `~/.config/opencode/plugins/` that calls `hol-guard hook --harness opencode`
    before bash and shell tools run, so package installs and secret-read commands are evaluated during the session
  - supports wrapper-mode management state plus a Guard-owned runtime overlay for native skill approval prompts
  - supports wrapper-mode `guard run opencode`
  - wrapper prompt screening is covered for benign debug prompts and risky secret-read prompts
  - keeps managed MCP tools on OpenCode native ask so the user can allow once, allow for the session, or reject inline
  - blocks newly introduced OpenCode MCP, plugin, and skill artifacts before launch when local Guard policy requires
    approval
  - native shell and managed MCP package-manager calls now share the same package-request evaluator, evidence fields, and approval-center copy
- `kimi`
  - detects `~/.kimi-code/config.toml` and workspace `.kimi-code/config.toml`
  - detects `~/.kimi-code/mcp.json` MCP server registrations
  - detects existing `[[hooks]]` entries in Kimi Code's TOML config
  - installs Guard-owned `PreToolUse`, `UserPromptSubmit`, `PostToolUse`, `SessionStart`, and `Stop` hooks in `~/.kimi-code/config.toml` by calling `hol-guard hook --harness kimi`
  - blocks dangerous tool calls and prompts by returning exit code `2` and a JSON `permissionDecision: "deny"` response in `hookSpecificOutput`
  - fails open if a hook crashes or times out, so Kimi Code keeps working when Guard is unreachable
  - uses the same JSON stdin/stdout wire protocol as Codex and Claude Code

Approval tiers:

1. native harness approval when the harness already has strong permission controls
2. local Guard approval center on `127.0.0.1`
3. terminal approval resolution through `hol-guard approvals`

The harness adapters are designed to prefer discovery and reversible overlay behavior over invasive config mutation.

The Guard Surface Server now provides one shared runtime shape across harnesses:

- session attach
- operation start and status updates
- approval request items
- approval-center lease and heartbeat tracking
- resume or completion after approval

Runtime intent protections:

- Guard evaluates prompt and tool intent for secret-bearing files beyond `.env`, including SSH, AWS, kubeconfig, Docker, npm, and Python credential files.
- Guard flags exfiltration verbs, staged transfer intent, destructive filesystem mutation intent, subprocess expansion, and explicit Guard bypass intent.
- Prompt intent is converted into typed prompt-request artifacts so it follows the same policy, approval, receipt, and cloud sync pipeline as other artifact decisions.
- Package-manager shell and MCP actions now persist package manager, primary package, install intent, and the final pre-execution Guard result in the shared runtime envelope before an approval request is queued.
- Saved artifact-level package blocks now stop retries without creating a fresh approval request, so deny decisions stay sticky until a new allow rule or exception exists.
- Skill protection flags package-manager install instructions inside `SKILL.md` content before the agent executes the skill.
- Supply-chain evidence now records harness, agent app, redacted command shape, and workspace fingerprint so Cloud and local receipts stay attributable.

Device identity model:

- Guard sync now uses an opaque local installation ID instead of hostname-derived IDs.
- The local label is user-controlled through `hol-guard device label set <label>`.
- Installation IDs can be rotated with `hol-guard device rotate` without breaking local policy history.

Explicit non-support:

- Guard does not claim VS Code Copilot extension-host interception.
- A VS Code Copilot inline tool prompt by itself is not proof that Guard blocked the action; that prompt can come from VS Code's own permission surface.
- Current Copilot proof should come from Guard-owned CLI hook responses, Guard runtime receipts, or an MCP client that explicitly answers Guard elicitation.
- Guard does not add `guard run vscode-copilot`.
- Guard treats `~/.copilot/*` as read-only detection input and does not auto-write user-level Copilot config.
- Guard does not add Cisco AIBOM runtime or policy integration in this pass. If revisited later, AIBOM belongs on evidence or export surfaces.
- Guard does not currently ship a Goose adapter in this repository. There is no Goose detection, install, hook, or proxy surface here to protect yet.

## Protection Contract Summary

Generated from `src/codex_plugin_scanner/guard/adapters/contracts.py`.

| Harness | Install Aliases | Native Approval | Browser Fallback | Resume | Event Surfaces |
|---------|-----------------|-----------------|------------------|--------|----------------|
| `codex` | `codex` | ✅ | ✅ | ✅ | shell, prompt, mcp_tool, file_read |
| `claude-code` | `claude-code`, `claude` | ✅ | ✅ | ✅ | shell, prompt, mcp_tool, file_read |
| `opencode` | `opencode` | ❌ | ✅ | ❌ | shell, mcp_tool |
| `copilot` | `copilot` | ✅ | ✅ | ✅ | shell, prompt |
| `cursor` | `cursor` | ❌ | ✅ | ❌ | shell, mcp_tool, file_read |
| `gemini` | `gemini` | ❌ | ✅ | ❌ | shell, mcp_tool |
| `hermes` | `hermes` | ❌ | ✅ | ❌ | shell, mcp_tool, prompt |
| `openclaw` | `openclaw` | ❌ | ✅ | ❌ | mcp_tool |
| `antigravity` | `antigravity` | ❌ | ✅ | ❌ | mcp_tool, prompt |
| `kimi` | `kimi`, `kimi-code`, `kimi-cli` | ❌ | ✅ | ❌ | shell, prompt |
