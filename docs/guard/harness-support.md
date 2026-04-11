# Harness Support Matrix

Current Guard support in this repo:

- `codex`
  - detects global and project `config.toml`
  - parses configured MCP servers
  - supports wrapper-mode `guard run codex`
  - uses the local approval center for blocked artifact changes today
- `claude-code`
  - detects global and project settings, hooks, `.mcp.json`, and workspace agents
  - supports local hook install and uninstall in `.claude/settings.local.json`
  - is the best current harness for graceful approval deferral
- `cursor`
  - detects global and project `mcp.json`
  - supports wrapper-mode management state
  - leaves native Cursor tool approval in place and focuses Guard on artifact trust
- `gemini`
  - detects local extension manifests and embedded MCP server declarations
  - supports wrapper-mode management state
  - falls back to the local approval center when Guard blocks a launch
- `opencode`
  - detects global and project config plus workspace commands
  - supports wrapper-mode management state
  - respects OpenCode permission rules and uses Guard for package-level policy

Approval tiers:

1. native harness approval when the harness already has strong permission controls
2. local Guard approval center on `127.0.0.1`
3. terminal approval resolution through `hol-guard approvals`

The harness adapters are designed to prefer discovery and reversible overlay behavior over invasive config mutation.
