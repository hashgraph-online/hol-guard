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
- CLI DX contract tests for summary-first `run`, `explain`, `doctor`, `scan`, `lint`, and `verify` output
- scanner command consistency tests for nonexistent target handling across `scan`, `lint`, `verify`, `doctor`, and `submit`
- tier 2 package-request regressions for Cargo, Go, Maven, Gradle, Composer, RubyGems, system package managers, and unsupported-manager fallback
- support-matrix assertions for `hol-guard cloud sync-intel` so CLI and Cloud surface `Protected`, `Beta`, and `Monitor-only` labels consistently
- Phase 14 harness package-install regressions for the shared runtime action contract, package-hook no-run behavior, MCP package routing, skill install detection, retry safety, resume targeting, approval dedupe, and evidence source fields

## Phase 14 harness package-install proof

Run this focused proof bundle when you touch harness package-install coverage:

```bash
pytest \
  tests/test_guard_runtime_actions_phase14.py \
  tests/test_guard_mcp_package_proxy_phase14.py \
  tests/test_guard_package_hook_phase14.py \
  tests/test_guard_package_resume_phase14.py \
  tests/test_guard_approval_store_phase14.py \
  tests/test_guard_skill_protection_phase14.py -q
```

This proof bundle covers:

- Codex, Claude Code, OpenCode, Copilot, Gemini, Hermes, and OpenClaw package-manager hook interception before execution
- Cursor, OpenCode, Hermes, and OpenClaw MCP package-manager routing through the supply-chain evaluator
- consistent package block copy and dashboard link output across managed harnesses
- saved block retry safety so denied package actions do not open a fresh approval request
- Codex approval resume targeting for the matching package request while other queued package approvals remain pending
- approval queue compatibility when package metadata is added to action envelopes, plus simultaneous duplicate and distinct package-request inserts
- skill-content detection for package-manager install instructions
- evidence assertions for harness, agent app, redacted command shape, and workspace fingerprint

Repo-scoped gap:

- Goose has no adapter, config surface, binary harness, or MCP proxy integration in this repository today, so there is no local Phase 14 package-install proof to run for Goose yet.

## CI wrapper examples

Use `hol-guard protect` in CI whenever a workflow installs dependencies directly:

```yaml
- name: Install dependencies through HOL Guard
  run: hol-guard protect -- npm ci
```

Example `.github/workflows` sequence with the scanner action:

```yaml
jobs:
  guard-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - name: Install dependencies through HOL Guard
        run: hol-guard protect -- npm ci
      - name: Run scanner action
        uses: hashgraph-online/ai-plugin-scanner-action@v1
        with:
          plugin_dir: "."
```

## Supply-chain ecosystem support labels

Use `hol-guard cloud sync-intel` after a successful bundle refresh to inspect current package-manager coverage:

- **Protected**: `npm`, `PyPI`
- **Beta**: `Cargo`, `Go modules`, `Maven/Gradle`, `Composer`, `RubyGems`
- **Monitor-only**: Docker base images, GitHub Actions, system packages, and unsupported package managers

Monitor-only means Guard still records the request and runs generic risk detection, but it does not claim signed-advisory blocking where no exact ecosystem coverage exists yet.

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
- `hol-guard status`
- `hol-guard connect`
- `hol-guard connect status`
- `hol-guard connect repair`
- `hol-guard sync`
- `hol-guard cloud sync-intel`
- `pytest tests/test_guard_runtime_actions_phase14.py tests/test_guard_mcp_package_proxy_phase14.py tests/test_guard_package_hook_phase14.py tests/test_guard_package_resume_phase14.py tests/test_guard_approval_store_phase14.py tests/test_guard_skill_protection_phase14.py -q`
- `hol-guard explain install-connect`
- `hol-guard explain codex:project:<artifact-name>`
- `hol-guard diff codex`
- `hol-guard events`
- `hol-guard abom`
- `plugin-scanner scan tests/fixtures/good-plugin --format json`
- `plugin-scanner lint tests/fixtures/good-plugin --format json`
- `plugin-scanner verify tests/fixtures/good-plugin --format json`
- `plugin-scanner doctor tests/fixtures/good-plugin --component mcp --bundle dist/doctor.zip`
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

## Red-Team Fixture Suite (T646)

Run the red-team corpus to validate fixture safety and manifest integrity:

```bash
pytest tests/test_guard_red_team.py tests/test_guard_canary_fixtures.py -q
```

This verifies:
- All malicious fixtures use only `hol-fake-*` sentinel values and route to the canary domain
- All benign fixtures contain no exfil patterns or real key prefixes
- Every fixture listed in `expected-decisions.json` exists on disk
- No local usernames, real paths, or real tokens appear in any fixture

To run only the red-team manifest and safety tests:

```bash
pytest tests/test_guard_red_team.py -q
```

To run the full test suite including red-team:

```bash
pytest -q
```
