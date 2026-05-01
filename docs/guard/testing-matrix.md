# Guard Testing Matrix

Automated coverage in this phase includes:

- Guard CLI behavior tests for detect, scan, run, diff, receipts, install, uninstall, login, and sync
- Guard product-flow tests for `hol-guard start`, `hol-guard status`, and launcher shim creation
- prompt-risk regressions for Codex, Cursor, Gemini, and OpenCode wrapper launches
- native prompt-hook regressions for Claude Code and Copilot hook events
- SQLite persistence through real command execution in temporary homes and workspaces
- consumer-mode JSON contract generation against scanner fixtures
- local HTTP sync against a live in-process server instead of mocked transport
- scheduled self-hosted harness smoke through `.github/workflows/harness-smoke.yml`

Manual verification should include:

- `hol-guard start`
- `hol-guard status`
- `hol-guard detect codex --json`
- `hol-guard detect cursor --json`
- `hol-guard detect antigravity --json`
- `hol-guard detect gemini --json`
- `hol-guard detect opencode --json`
- `hol-guard detect openclaw --json`
- `hol-guard install opencode --json`
- `hol-guard install openclaw --json`
- `hol-guard update --dry-run --json`
- `hol-guard run cursor --dry-run --default-action allow --json`
- `hol-guard run gemini --dry-run --default-action allow --json`
- `hol-guard run opencode --dry-run --default-action allow --json`
- `hol-guard run opencode --default-action require-reapproval --json`
- `hol-guard approvals --json`
- `hol-guard install codex`
- `hol-guard run codex --dry-run --default-action allow --json`
- `hol-guard receipts`
- `codex mcp list`
- `cursor-agent mcp list`
- `antigravity --help`
- `gemini --help`
- `opencode --help`
- `opencode run --help`
- `openclaw --help`

First-party canaries for local manual validation:

- a local `hashnet-mcp-js` checkout wired into Codex, Cursor, or Claude Code config
- a local `registry-broker-skills` checkout for scanner fixtures and trust review

Claude Code smoke tests remain conditional on the local `claude` binary being available.

OpenCode manual validation should include one isolated local workspace where you prove all of the following against the
real `opencode` binary:

- a newly added MCP server blocks before launch
- a newly added skill blocks before launch
- a newly added plugin blocks before launch
- a blocked prompt request queues an approval
- approving that request lets Guard hand off to `opencode run --dir <workspace> ...`

OpenClaw manual validation should include one isolated local gateway config where you prove all of the following against
the real `openclaw` binary:

- an open DM policy with wildcard senders is surfaced as a channel risk
- a remote MCP endpoint is surfaced as a network risk
- a newly added workspace skill blocks before launch when policy requires reapproval
- `hol-guard install openclaw` creates the managed overlay and pre-tool bundle under Guard home
- approving a blocked OpenClaw request resolves through native-or-center delivery without mutating user config

Nightly release-bar coverage should include:

- Codex on a self-hosted Linux runner
- Claude Code or Cursor on a self-hosted macOS runner
- Gemini or OpenCode on a self-hosted Windows runner
- a release gate that only passes when those harness families stay green
