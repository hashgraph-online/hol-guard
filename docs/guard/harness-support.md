# Harness Support Matrix

Current Guard support in this repo:

- `codex`
  - detects global and project `config.toml`
  - parses configured MCP servers
  - supports wrapper-mode `guard run codex`
  - uses same-chat MCP elicitation for live managed MCP tool approvals in the interactive CLI and Codex App
  - falls back to the local approval center only for nonresponsive or headless Codex sessions such as `codex exec`
- `claude-code`
  - detects global and project settings, hooks, `.mcp.json`, and workspace agents
  - supports local hook install and uninstall in `.claude/settings.local.json`
  - is the best current harness for graceful approval deferral
- `copilot`
  - detects read-only user config in `~/.copilot/config.json` and `~/.copilot/mcp-config.json`
  - detects workspace `.vscode/mcp.json` as documented MCP artifact input only
  - detects repo-local Copilot CLI hooks from `.github/hooks/*.json`
  - installs and removes Guard-owned repo hooks in `.github/hooks/hol-guard-copilot.json`
  - supports wrapper-mode `guard run copilot`
- `cursor`
  - detects global and project `mcp.json`
  - supports wrapper-mode management state
  - leaves native Cursor tool approval in place and focuses Guard on artifact trust
- `antigravity`
  - detects Antigravity user settings, installed extension profiles, and Antigravity-owned MCP and skill roots
  - supports wrapper-mode management state
  - uses the local approval center for blocked artifact changes today
- `gemini`
  - detects `.gemini/settings.json`, local extension manifests, embedded MCP declarations, hooks, and Gemini skill directories
  - supports wrapper-mode management state
  - falls back to the local approval center when Guard blocks a launch
- `hermes`
  - detects Hermes skills plus MCP servers from `~/.hermes/config.yaml` and `~/.hermes/mcp_servers.json`
  - supports `hol-guard hermes bootstrap` and a Guard-managed Hermes overlay bundle under Guard home
  - rewrites managed Hermes MCP entries through Guard’s existing proxy path and uses native-or-center delivery when the managed bundle is present
  - blocks sensitive file reads and Docker-sensitive native pre-tool actions through the existing Guard hook path
- `opencode`
  - detects global and project config, MCP servers, config-defined commands, markdown commands, npm plugins, local
    plugin files, and OpenCode-compatible skill directories
  - supports wrapper-mode management state plus a Guard-owned runtime overlay for native skill approval prompts
  - supports wrapper-mode `guard run opencode`
  - keeps managed MCP tools on OpenCode native ask so the user can allow once, allow for the session, or reject inline
  - blocks newly introduced OpenCode MCP, plugin, and skill artifacts before launch when local Guard policy requires
    approval

Approval tiers:

1. native harness approval when the harness already has strong permission controls
2. local Guard approval center on `127.0.0.1`
3. terminal approval resolution through `hol-guard approvals`

The harness adapters are designed to prefer discovery and reversible overlay behavior over invasive config mutation.

Explicit non-support:

- Guard does not claim VS Code Copilot extension-host interception.
- A VS Code Copilot inline tool prompt by itself is not proof that Guard blocked the action; that prompt can come from VS Code's own permission surface.
- Current Copilot proof should come from Guard-owned CLI hook responses, Guard runtime receipts, or an MCP client that explicitly answers Guard elicitation.
- Guard does not add `guard run vscode-copilot`.
- Guard treats `~/.copilot/*` as read-only detection input and does not auto-write user-level Copilot config.
- Guard does not add Cisco AIBOM runtime or policy integration in this pass. If revisited later, AIBOM belongs on evidence or export surfaces.
