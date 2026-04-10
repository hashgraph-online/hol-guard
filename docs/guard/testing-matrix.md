# Guard Testing Matrix

Automated coverage in this phase includes:

- Guard CLI behavior tests for detect, scan, run, diff, receipts, install, uninstall, login, and sync
- SQLite persistence through real command execution in temporary homes and workspaces
- consumer-mode JSON contract generation against scanner fixtures
- local HTTP sync against a live in-process server instead of mocked transport

Manual verification should include:

- `guard detect codex --json`
- `guard detect cursor --json`
- `guard detect gemini --json`
- `guard detect opencode --json`
- `guard run codex --dry-run --default-action allow --json`
- `codex mcp list`
- `cursor-agent mcp list`
- `gemini --help`
- `opencode --help`

Claude Code smoke tests remain conditional on the local `claude` binary being available.
