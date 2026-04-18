# HOL Guard

[![HOL Guard Version](https://img.shields.io/pypi/v/hol-guard.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/hol-guard/)
[![Plugin Scanner Version](https://img.shields.io/pypi/v/plugin-scanner.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/plugin-scanner/)
[![HOL Guard Downloads](https://img.shields.io/pypi/dm/hol-guard?logo=pypi&logoColor=white)](https://pypi.org/project/hol-guard/)
[![Plugin Scanner Downloads](https://img.shields.io/pypi/dm/plugin-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/plugin-scanner/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#install-the-package-you-need)
[![CI](https://github.com/hashgraph-online/ai-plugin-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hashgraph-online/ai-plugin-scanner/actions/workflows/ci.yml)
[![Publish](https://github.com/hashgraph-online/ai-plugin-scanner/actions/workflows/publish.yml/badge.svg)](https://github.com/hashgraph-online/ai-plugin-scanner/actions/workflows/publish.yml)
[![Container Image](https://img.shields.io/badge/ghcr-ai--plugin--scanner-2496ED?logo=docker&logoColor=white)](https://github.com/hashgraph-online/ai-plugin-scanner/pkgs/container/ai-plugin-scanner)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/ai-plugin-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/ai-plugin-scanner)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/hashgraph-online/ai-plugin-scanner?style=social)](https://github.com/hashgraph-online/ai-plugin-scanner/stargazers)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-D7FF64.svg)](https://github.com/astral-sh/ruff)

| ![Hashgraph Online Logo](https://hol.org/brand/Logo_Whole_Dark.png) | **Protect your harness locally with `hol-guard`.** Use `plugin-scanner` when you need maintainer and CI checks for plugins, skills, MCP servers, and marketplace packages.<br><br>[PyPI Package (`hol-guard`)](https://pypi.org/project/hol-guard/)<br>[PyPI Package (`plugin-scanner`)](https://pypi.org/project/plugin-scanner/)<br>[HOL Plugin Registry](https://hol.org/registry/plugins)<br>[HOL GitHub Organization](https://github.com/hashgraph-online)<br>[Report an Issue](https://github.com/hashgraph-online/ai-plugin-scanner/issues) |
| :--- | :--- |

## Start Here

| If you want to... | Install | Start with |
| :--- | :--- | :--- |
| protect Codex, Claude Code, Copilot CLI, Hermes, Cursor, Gemini, or OpenCode before tools run | `hol-guard` | `hol-guard start` |
| lint and verify packages in CI before release | `plugin-scanner` | `plugin-scanner verify .` |

## Guard Quickstart

```bash
pipx run hol-guard bootstrap
pipx run hol-guard hermes bootstrap
pipx run hol-guard run codex --dry-run
pipx run hol-guard run codex
pipx run hol-guard approvals
pipx run hol-guard receipts
```

What you get from Guard:

- Detects local harness config on your machine
- Records a baseline before you trust a tool
- Pauses cleanly on new or changed artifacts before launch
- Queues blocked changes in a localhost approval center when the harness cannot prompt inline
- Stores receipts locally so you can review decisions later
- Keeps sync optional until you actually want shared history

See [docs/guard/get-started.md](docs/guard/get-started.md) for the full local flow.

<details>
<summary>Guard commands at a glance</summary>

- `hol-guard start`
  Shows the next step for the harnesses Guard found.
- `hol-guard bootstrap`
  Detects the best local harness, starts the approval center, and installs Guard in front of it.
- `hol-guard hermes bootstrap`
  Installs the Guard-managed Hermes overlay bundle directly.
- `hol-guard status`
  Shows what Guard is watching now.
- `hol-guard install <harness>`
  Creates the launcher shim for that harness.
- `hol-guard update`
  Updates the installed `hol-guard` package in the current environment.
- `hol-guard run <harness> --dry-run`
  Records the current state once before you trust it.
- `hol-guard run <harness>`
  Reviews changes before launch and hands blocked sessions to the approval center when needed.
- `hol-guard approvals`
  Lists pending approvals or resolves them from the terminal.
- `hol-guard receipts`
  Shows local approval and block history.

</details>

<details>
<summary>Harness approval strategy</summary>

- `claude-code`
  Guard prefers Claude hooks first, then the local approval center when the shell cannot prompt.
- `copilot`
  Guard can wrap the `copilot` CLI, detect `~/.copilot/config.json`, `~/.copilot/mcp-config.json`, workspace `.vscode/mcp.json`, and install repo-local `.github/hooks/hol-guard-copilot.json` hook entries for documented `preToolUse` and `postToolUse` events.
- `codex`
  Guard asks inline in the same Codex chat when the interactive CLI or Codex App can answer MCP elicitations, and falls back to the local approval center for `codex exec` or any nonresponsive session.
- `cursor`
  Guard respects Cursor’s native tool approval and focuses on artifact trust before launch.
- `opencode`
  Guard authors package-level policy while OpenCode keeps native allow or deny rules.
- `hermes`
  Guard installs a managed Hermes overlay bundle, routes MCP servers through Guard proxies, and prefers native-or-center delivery for blocked requests.
- `gemini`
  Guard scans extensions and falls back to the local approval center for blocked changes.

</details>

## Scanner Quickstart

```bash
pipx install plugin-scanner
plugin-scanner lint .
plugin-scanner verify .
```

```yaml
# GitHub Actions PR gate
- name: AI plugin quality gate
  uses: hashgraph-online/ai-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    fail_on_severity: high
    min_score: 80
```

When to add `plugin-scanner`:

- You publish plugins, skills, or marketplace packages
- You want a CI gate before release
- You need SARIF, verification payloads, or submission artifacts

If your repository uses a Codex marketplace root like `.agents/plugins/marketplace.json`, keep `plugin_dir: "."`. The scanner will discover local `./plugins/...` entries automatically, scan each local plugin manifest, and skip remote marketplace entries instead of treating the repo root as a single plugin.

## Need More Detail?

- Contributor setup: jump to [Development](#development)
- Local Guard docs: [docs/guard/get-started.md](docs/guard/get-started.md)
- GitHub Action docs: [hashgraph-online/ai-plugin-scanner-action](https://github.com/hashgraph-online/ai-plugin-scanner-action)
- Registry and trust references: keep reading below

<details>
<summary>Scanner reference: trust scoring, installs, ecosystems, and CLI commands</summary>

## How Trust Scoring Works

The scanner now emits explicit trust provenance alongside the quality grade:

- bundled skills use the published HCS-28 baseline adapter ids, weights, and denominator rules directly
- MCP configuration trust uses the same HCS-style adapter, weight, and contribution-mode pattern locally
- top-level Codex plugin trust uses the same HCS-style adapter, weight, and contribution-mode pattern locally

Current local specs:

- [Skill Trust Local Draft](docs/trust/skill-trust-local.md)
- [MCP Trust Draft](docs/trust/mcp-trust-draft.md)
- [Codex Plugin Trust Draft](docs/trust/plugin-trust-draft.md)

This keeps the quality grade and the trust score separate. Signals like `SECURITY.md` remain visible, but their weight is now a named adapter weight rather than an inferred side effect of raw category points.

## Quick Start For Contributors

```bash
git clone https://github.com/hashgraph-online/ai-plugin-scanner.git
cd ai-plugin-scanner
uv sync --extra dev --extra cisco
pytest -q
```

Use `uv sync --extra dev --python 3.10` when you need the lean baseline path without the Cisco MCP extra.

## Install The Package You Need

### Lean baseline install

Guard package:

```bash
pip install hol-guard
```

Scanner package:

```bash
pip install plugin-scanner
```

The lean baseline keeps Python 3.10 support intact and always includes the shipped `cisco-ai-skill-scanner` integration.

### Full Cisco coverage

Install the Cisco extra on Python 3.11+ when you want static MCP coverage in addition to the baseline skill scanner:

```bash
pip install "hol-guard[cisco]"
```

```bash
pip install "plugin-scanner[cisco]"
```

`cisco-ai-mcp-scanner` stays in the optional `cisco` extra because it is Python 3.11+ only and adds a heavier YARA-backed install surface than the lean baseline should require.

On Guard surfaces, the Cisco extra adds optional offline evidence to `hol-guard scan`, `hol-guard preflight`, and `hol-guard explain <path>`. Use `--cisco-mode {auto,on,off}` to control that consumer-mode evidence path for local artifact scans. `hol-guard run` and Guard runtime prompt/file-read protection remain native Guard behavior in this pass.

Guard does not add Cisco AIBOM runtime integration in this pass. If AIBOM support returns later, it should stay on evidence or export surfaces rather than Guard blocking or approval logic.

### Cisco package status

Credit to [Cisco AI Defense](https://github.com/cisco-ai-defense) for open-sourcing the packages below.

| Package | Status in this repo | Notes |
| :--- | :--- | :--- |
| `cisco-ai-skill-scanner` | shipped by default | Included in the lean baseline install. |
| `cisco-ai-mcp-scanner` | shipped via `[cisco]` | Recommended for full Cisco coverage on Python 3.11+, including repo-controlled CI and Docker. |
| `cisco-ai-a2a-scanner` | deferred | Requires live A2A endpoints and is not added in this pass. |
| `cisco-aibom` | deferred | No Guard runtime integration in this pass. Revisit later only for evidence or export workflows. |

If you want both tools in one shell during local development:

```bash
pipx install hol-guard
pipx install plugin-scanner
```

Container-first environments can use the published image instead. The repo-controlled image installs a lock-derived Cisco dependency set on Python 3.12 so the container has full static Cisco coverage by default.

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  ghcr.io/hashgraph-online/ai-plugin-scanner:<version> \
  scan /workspace --format text
```

Command names by package:

```bash
hol-guard start
plugin-scanner verify .
```

## Ecosystem Support

| Ecosystem | Detection Surfaces |
| :--- | :--- |
| Codex | `.codex-plugin/plugin.json`, `marketplace.json`, `.agents/plugins/marketplace.json` |
| Claude Code | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` |
| Gemini CLI | `gemini-extension.json`, `commands/**/*.toml` |
| OpenCode | `opencode.json`, `opencode.jsonc`, `.opencode/commands`, `.opencode/plugins` |

Use `--ecosystem auto` (default) to scan all detected packages in a repository, or select a single ecosystem explicitly.

## What The Scanner Checks

`plugin-scanner` supports a full quality suite:

- `scan` for full-surface security and release analysis
- `lint` for rule-oriented authoring feedback
- `verify` for runtime and install-surface readiness checks
- `submit` for artifact-backed submission gating
- `doctor` for targeted diagnostics and troubleshooting bundles

The scanner evaluates only the surfaces a plugin actually exposes, then normalizes the final score across applicable checks. A plugin is not rewarded or penalized for optional surfaces it does not ship.

| Category | Max Points | Coverage |
| :--- | :--- | :--- |
| Manifest Validation | 31 | `plugin.json`, required fields, semver, kebab-case, recommended metadata, interface metadata, interface links and assets, safe declared paths |
| Security | 36 | `SECURITY.md`, `LICENSE`, hardcoded secret detection, dangerous MCP commands, MCP transport hardening, risky approval defaults, Cisco MCP scan status, elevated MCP findings, MCP analyzability |
| Operational Security | 20 | SHA-pinned GitHub Actions, `write-all`, privileged untrusted checkout patterns, Dependabot, dependency lockfiles |
| Best Practices | 15 | `README.md`, skills directory, `SKILL.md` frontmatter, committed `.env`, `.codexignore` |
| Marketplace | 15 | `.agents/plugins/marketplace.json` validity, legacy `marketplace.json` compatibility, policy fields, safe source paths |
| Skill Security | 15 | Cisco integration status, elevated skill findings, analyzability |
| Code Quality | 10 | `eval`, `new Function`, shell-injection patterns |

## CLI Usage

```bash
# Scan a plugin directory
plugin-scanner ./my-plugin

# Auto-detect all supported ecosystems inside a repo (default)
plugin-scanner ./plugins-repo --ecosystem auto

# Scan only Claude package surfaces
plugin-scanner ./plugins-repo --ecosystem claude

# List supported ecosystems
plugin-scanner --list-ecosystems

# Output JSON
plugin-scanner ./my-plugin --json

# Write a SARIF report for GitHub code scanning
plugin-scanner ./my-plugin --format sarif --output plugin-scanner.sarif

# Fail CI on findings at or above high severity
plugin-scanner ./my-plugin --fail-on-severity high

# Require Cisco skill scanning with a strict policy
plugin-scanner ./my-plugin --cisco-skill-scan on --cisco-policy strict

# Require optional Cisco MCP static analysis
plugin-scanner ./my-plugin --cisco-mcp-scan on
```

## Quality Suite Commands

```bash
# Summary scan (legacy form still works)
plugin-scanner scan ./my-plugin --format json --profile public-marketplace

# Scan a multi-plugin repo from the marketplace root
plugin-scanner scan . --format json

# Rule-oriented lint (with optional mechanical fixes)
plugin-scanner lint ./my-plugin --list-rules
plugin-scanner lint ./my-plugin --explain README_MISSING
plugin-scanner lint ./my-plugin --fix --profile strict-security

# Runtime readiness verification
plugin-scanner verify ./my-plugin --format json
plugin-scanner verify . --format json
plugin-scanner verify ./my-plugin --online --format text

# Artifact-backed submission gate
plugin-scanner submit ./my-plugin --profile public-marketplace --attest dist/plugin-quality.json

# Diagnostic bundle
plugin-scanner doctor ./my-plugin --component mcp --bundle dist/doctor.zip
```

</details>

<details>
<summary>Advanced reference: specs, action publishing, automation, and examples</summary>

## Codex Spec Alignment

The scanner follows the current Codex plugin packaging conventions more closely:

- local manifest paths should use `./` prefixes
- `.agents/plugins/marketplace.json` is the preferred marketplace manifest location
- root `marketplace.json` is still supported in compatibility mode
- `interface` metadata no longer requires an undocumented `type` field
- `verify` performs an MCP initialize handshake before probing declared capabilities

`lint --fix` preserves or adds the documented `./` prefixes instead of stripping them away.

For repo-scoped marketplaces, `scan`, `lint`, `verify`, and `doctor` can target the repository root directly. `submit` remains intentionally single-plugin so the emitted artifact points at one concrete plugin package.

## Config + Baseline Example

```toml
# .plugin-scanner.toml
[scanner]
profile = "public-marketplace"
baseline_file = "baseline.txt"
ignore_paths = ["tests/*", "fixtures/*"]

[rules]
disabled = ["README_MISSING"]
severity_overrides = { CODEXIGNORE_MISSING = "low" }
```

## Example Output

```text
🔗 Plugin Scanner v2.0.0
Scanning: ./my-plugin

── Manifest Validation (31/31) ──
  ✅ plugin.json exists                           +4
  ✅ Valid JSON                                   +4
  ✅ Required fields present                      +5
  ✅ Version follows semver                       +3
  ✅ Name is kebab-case                           +2
  ✅ Recommended metadata present                 +4
  ✅ Interface metadata complete if declared      +3
  ✅ Interface links and assets valid if declared +3
  ✅ Declared paths are safe                      +3

── Security (16/16) ──
  ✅ SECURITY.md found                            +3
  ✅ LICENSE found                                +3
  ✅ No hardcoded secrets                         +7
  ✅ No dangerous MCP commands                    +0
  ✅ MCP remote transports are hardened           +0
  ✅ No approval bypass defaults                  +3

── Operational Security (0/0) ──
  ✅ Third-party GitHub Actions pinned to SHAs    +0
  ✅ No write-all GitHub Actions permissions      +0
  ✅ No privileged untrusted checkout patterns    +0
  ✅ Dependabot configured for automation surfaces +0
  ✅ Dependency manifests have lockfiles          +0

── Skill Security (15/15) ──
  ✅ Cisco skill scan completed                   +3
  ✅ No elevated Cisco skill findings             +8
  ✅ Skills analyzable                            +4

Findings: critical:0, high:0, medium:0, low:0, info:0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Score: 100/100 (A - Excellent)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Report Formats

| Format | Use Case |
| :--- | :--- |
| `text` | Human-readable terminal summary with category totals and findings |
| `json` | Structured integrations and findings for tooling and dashboards |
| `markdown` | Pull request, issue, or review-ready summaries |
| `sarif` | GitHub code scanning uploads and security automation |

## Scanner Signals

The scanner currently detects or validates:

- Hardcoded secrets such as AWS keys, GitHub tokens, OpenAI keys, Slack tokens, GitLab tokens, and generic password or token patterns
- Dangerous MCP command patterns such as `rm -rf`, `sudo`, `curl|sh`, `wget|sh`, `eval`, `exec`, and PowerShell or `cmd /c` shells
- Insecure MCP remotes, including non-HTTPS endpoints and non-loopback HTTP transports
- Risky Codex defaults such as approval bypass and unrestricted sandbox defaults inside shipped plugin config or docs
- Publishability issues in `interface` metadata, HTTPS links, and declared asset paths
- Workflow hardening gaps including unpinned third-party actions, `write-all`, privileged checkout patterns, missing Dependabot, and missing lockfiles
- Skill-level issues surfaced by Cisco `skill-scanner` when the optional integration is installed
- Static MCP findings surfaced by Cisco `mcp-scanner` when the optional `cisco` extra is installed

## CI And Automation

Add the scanner to a plugin repository CI job:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan-plugin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: hashgraph-online/ai-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          mode: scan
          profile: public-marketplace
          min_score: 80
          fail_on_severity: high
          format: sarif
          upload_sarif: true
```

For a multi-plugin repo, the same workflow can stay pointed at `plugin_dir: "."` as long as the repository has `.agents/plugins/marketplace.json` with local `./plugins/...` entries.

For repo-controlled validation in this repository, Linux jobs that target full coverage install the `cisco` extra on Python 3.12, while the baseline matrix keeps Python 3.10 compatibility explicit.

Local pre-commit style hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: plugin-scanner
        name: Plugin Scanner
        entry: plugin-scanner
        language: system
        types: [directory]
        pass_filenames: false
        args: ["./"]
```

## GitHub Action

The Marketplace action lives in the dedicated repository [hashgraph-online/ai-plugin-scanner-action](https://github.com/hashgraph-online/ai-plugin-scanner-action).

This repository no longer vendors a local action bundle. Use the standalone action repository for `action.yml`, release notes, and action-specific documentation. The legacy alias [hashgraph-online/hol-codex-plugin-scanner-action](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action) remains available for existing workflows.
When you run the scanner in your own job instead of the packaged action, install `plugin-scanner[cisco]` on Python 3.11+ and set `CISCO_MCP_SCAN=auto` or `CISCO_MCP_SCAN=on` for full Cisco MCP coverage.

### Plugin Author Submission Flow

The action can also handle submission intake. A plugin repository can wire the scanner into CI so a passing scan opens or reuses a submission issue in [awesome-codex-plugins](https://github.com/hashgraph-online/awesome-codex-plugins).

It also emits automation-friendly machine outputs:

- `score`, `grade`, `grade_label`, `max_severity`, and `findings_total` as GitHub Action outputs
- a concise markdown summary in the job summary by default
- an optional machine-readable registry payload file for downstream registry, badge, or awesome-list automation

The intended path is:

1. Add the scanner action to plugin CI.
2. Require `min_score: 80` and a severity gate such as `fail_on_severity: high`.
3. Enable submission mode with a token that has `issues:write` on `hashgraph-online/awesome-codex-plugins`.
4. When the plugin clears the threshold, the action opens or reuses a submission issue.
5. The issue body includes machine-readable registry payload data, so registry automation can ingest the same submission event.

Example:

```yaml
permissions:
  contents: read

jobs:
  scan-plugin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Scan and submit if eligible
        id: scan
        uses: hashgraph-online/ai-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          min_score: 80
          fail_on_severity: high
          submission_enabled: true
          submission_score_threshold: 80
          submission_token: ${{ secrets.AWESOME_CODEX_PLUGINS_TOKEN }}

      - name: Print submission issue
        if: steps.scan.outputs.submission_performed == 'true'
        run: echo "${{ steps.scan.outputs.submission_issue_urls }}"
```

`submission_token` is required when `submission_enabled: true`. This flow is idempotent. If the plugin repository was already submitted, the action reuses the existing open issue instead of opening duplicates by matching an exact hidden plugin URL marker in the existing issue body.

### Registry Payload For Plugin Ecosystem Automation

If you want to feed the same scan into a registry, badge pipeline, or another plugin ecosystem automation step, request a registry payload file directly from the action:

```yaml
permissions:
  contents: read

jobs:
  scan-plugin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Scan plugin
        id: scan
        uses: hashgraph-online/ai-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          format: sarif
          output: ai-plugin-scanner.sarif
          registry_payload_output: ai-plugin-registry-payload.json

      - name: Show trust signals
        run: |
          echo "Score: ${{ steps.scan.outputs.score }}"
          echo "Grade: ${{ steps.scan.outputs.grade_label }}"
          echo "Max severity: ${{ steps.scan.outputs.max_severity }}"

      - name: Upload registry payload
        uses: actions/upload-artifact@v6
        with:
          name: ai-plugin-registry-payload
          path: ${{ steps.scan.outputs.registry_payload_path }}
```

The registry payload mirrors the submission data used by HOL ecosystem automation, so one scan can drive code scanning, review summaries, awesome-list intake, and registry trust ingestion.

## Development

```bash
pip install -e ".[dev,cisco]"
ruff check src tests
ruff format --check src
pytest -q
python -m build
```

Use `pip install -e ".[dev]"` or `uv sync --extra dev --python 3.10` when you need the lean baseline path without the Cisco MCP extra.

## Repository Workflows

- Matrix CI for Python `3.10` through `3.13`
- Package publishing via the `publish.yml` workflow
- OpenSSF Scorecard automation for repository hardening visibility

## Security

For disclosure and response policy, see [SECURITY.md](./SECURITY.md).

## Contributing

Contribution guidance lives in [CONTRIBUTING.md](./CONTRIBUTING.md).

## Maintainers

Maintained by HOL.

## Example: HOL Registry Broker Plugin

The [HOL Registry Broker Codex Plugin](https://github.com/hashgraph-online/registry-broker-codex-plugin) bridges Codex plugins with the [HOL Universal Registry](https://hol.org/registry/plugins), providing agent discovery, trust signals, and verified identity on Hedera.

[![Registry Broker trust badge](https://img.shields.io/endpoint?url=https%3A%2F%2Fhol.org%2Fapi%2Fregistry%2Fbadges%2Fplugin%3Fslug%3Dhol%252Fregistry-broker-codex-plugin%26metric%3Dtrust%26style%3Dflat)](https://hol.org/registry/plugins/hol%2Fregistry-broker-codex-plugin)

HOL Registry scores: **Trust 80** / **Review 83** / **Enforce 74**

```text
🔗 Plugin Scanner v2.0.0
Scanning: ./registry-broker-codex-plugin

── Manifest Validation (31/31) ──
  ✅ plugin.json exists                           +4
  ✅ Valid JSON                                   +4
  ✅ Required fields present                      +5
  ✅ Version follows semver                       +3
  ✅ Name is kebab-case                           +2
  ✅ Recommended metadata present                 +4
  ✅ Interface metadata complete if declared      +3
  ✅ Interface links and assets valid if declared +3
  ✅ Declared paths are safe                      +3

── Security (24/24) ──
  ✅ SECURITY.md found                            +3
  ✅ LICENSE found                                +3
  ✅ No hardcoded secrets                         +7
  ✅ No dangerous MCP commands                    +3
  ✅ MCP remote transports are hardened           +3
  ✅ No approval bypass defaults                  +5

── Operational Security (20/20) ──
  ✅ Third-party GitHub Actions pinned to SHAs    +5
  ✅ No write-all GitHub Actions permissions      +5
  ✅ No privileged untrusted checkout patterns    +3
  ✅ Dependabot configured for automation surfaces +4
  ✅ Dependency manifests have lockfiles          +3

── Best Practices (15/15) ──
  ✅ README.md found                             +5
  ✅ Skills directory present                    +3
  ✅ SKILL.md frontmatter valid                  +4
  ✅ No committed .env                           +2
  ✅ .codexignore found                          +1

── Marketplace (15/15) ──
  ✅ marketplace.json valid                      +5
  ✅ Policy fields present                       +5
  ✅ Marketplace sources are safe                +5

── Skill Security (15/15) ──
  ✅ Cisco skill scan completed                  +3
  ✅ No elevated Cisco skill findings            +8
  ✅ Skills analyzable                           +4

── Code Quality (10/10) ──
  ✅ No eval or Function constructor             +5
  ✅ No shell injection patterns                 +5

Findings: critical:0, high:0, medium:0, low:0, info:0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Score: 130/130
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Plugins that pass the scanner with a high score are candidates for listing in the [HOL Plugin Registry](https://hol.org/registry/plugins).

</details>

## Resources

- [HOL Plugin Registry](https://hol.org/registry/plugins)
- [HOL Standards Documentation](https://hol.org/docs/standards)
- [OpenAI Codex Plugin Documentation](https://developers.openai.com/codex/plugins)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Cisco AI Skill Scanner](https://pypi.org/project/cisco-ai-skill-scanner/)
- [Cisco AI MCP Scanner](https://pypi.org/project/cisco-ai-mcp-scanner/)
- [HOL GitHub Organization](https://github.com/hashgraph-online)

## License

Apache-2.0
