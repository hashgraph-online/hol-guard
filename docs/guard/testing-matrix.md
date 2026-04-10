# Guard Testing Matrix

Automated coverage in this phase includes:

- Guard CLI behavior tests for detect, scan, run, diff, receipts, install, uninstall, login, and sync
- Guard product-flow tests for `guard start`, `guard status`, and launcher shim creation
- SQLite persistence through real command execution in temporary homes and workspaces
- consumer-mode JSON contract generation against scanner fixtures
- local HTTP sync against a live in-process server instead of mocked transport

Manual verification should include:

- `guard start`
- `guard status`
- `guard detect codex --json`
- `guard detect cursor --json`
- `guard detect gemini --json`
- `guard detect opencode --json`
- `guard install codex`
- `guard run codex --dry-run --default-action allow --json`
- `guard receipts`
- `codex mcp list`
- `cursor-agent mcp list`
- `gemini --help`
- `opencode --help`

First-party canaries for local manual validation:

- a local `hashnet-mcp-js` checkout wired into Codex, Cursor, or Claude Code config
- a local `registry-broker-skills` checkout for scanner fixtures and trust review

Claude Code smoke tests remain conditional on the local `claude` binary being available.
