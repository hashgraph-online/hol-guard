# Harness Support Matrix

Current Guard support in this repo:

- `codex`
  - detects global and project `config.toml`
  - parses configured MCP servers
  - supports wrapper-mode `guard run codex`
- `claude-code`
  - detects global and project settings, hooks, `.mcp.json`, and workspace agents
  - supports local hook install and uninstall in `.claude/settings.local.json`
- `cursor`
  - detects global and project `mcp.json`
  - supports wrapper-mode management state
- `gemini`
  - detects local extension manifests and embedded MCP server declarations
  - supports wrapper-mode management state
- `opencode`
  - detects global and project config plus workspace commands
  - supports wrapper-mode management state

The harness adapters are designed to prefer discovery and reversible overlay behavior over invasive config mutation.
