# HOL Codex Plugin Scanner

[![PyPI Version](https://img.shields.io/pypi/v/codex-plugin-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/codex-plugin-scanner/)
[![Python Versions](https://img.shields.io/pypi/pyversions/codex-plugin-scanner)](https://pypi.org/project/codex-plugin-scanner/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/codex-plugin-scanner)](https://pypistats.org/packages/codex-plugin-scanner)
[![CI](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml)
[![Publish](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/publish.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/publish.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/codex-plugin-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/codex-plugin-scanner)
[![License](https://img.shields.io/github/license/hashgraph-online/codex-plugin-scanner)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/hashgraph-online/codex-plugin-scanner?style=social)](https://github.com/hashgraph-online/codex-plugin-scanner/stargazers)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-D7FF64.svg)](https://github.com/astral-sh/ruff)

| ![](https://raw.githubusercontent.com/hashgraph-online/standards-sdk-py/main/Hashgraph-Online.png) | Security, publishability, and security-ops scanner for [Codex plugins](https://developers.openai.com/codex/plugins). It scores the applicable plugin surface from `0-100`, emits structured findings, validates install-surface metadata, hardens MCP transport expectations, and can run Cisco-backed skill analysis for plugin skills.<br><br>[PyPI Package](https://pypi.org/project/codex-plugin-scanner/)<br>[HOL GitHub Repository](https://github.com/hashgraph-online/codex-plugin-scanner)<br>[Report an Issue](https://github.com/hashgraph-online/codex-plugin-scanner/issues) |
| :--- | :--- |

## Quick Start

```bash
git clone https://github.com/hashgraph-online/codex-plugin-scanner.git
cd codex-plugin-scanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Install

```bash
pip install codex-plugin-scanner
```

Cisco-backed skill scanning is optional:

```bash
pip install "codex-plugin-scanner[cisco]"
```

You can also run the scanner without a local install:

```bash
pipx run codex-plugin-scanner ./my-plugin
```

## What The Scanner Covers

The scanner evaluates only the surfaces a plugin actually exposes, then normalizes the final score across applicable checks. A plugin is not rewarded or penalized for optional surfaces it does not ship.

| Category | Max Points | Coverage |
| :--- | :--- | :--- |
| Manifest Validation | 31 | `plugin.json`, required fields, semver, kebab-case, recommended metadata, interface metadata, interface links and assets, safe declared paths |
| Security | 24 | `SECURITY.md`, `LICENSE`, hardcoded secret detection, dangerous MCP commands, MCP transport hardening, risky approval defaults |
| Operational Security | 20 | SHA-pinned GitHub Actions, `write-all`, privileged untrusted checkout patterns, Dependabot, dependency lockfiles |
| Best Practices | 15 | `README.md`, skills directory, `SKILL.md` frontmatter, committed `.env`, `.codexignore` |
| Marketplace | 15 | `marketplace.json` validity, policy fields, safe source paths |
| Skill Security | 15 | Cisco integration status, elevated skill findings, analyzability |
| Code Quality | 10 | `eval`, `new Function`, shell-injection patterns |

## CLI Usage

```bash
# Scan a plugin directory
codex-plugin-scanner ./my-plugin

# Output JSON
codex-plugin-scanner ./my-plugin --json

# Write a SARIF report for GitHub code scanning
codex-plugin-scanner ./my-plugin --format sarif --output codex-plugin-scanner.sarif

# Fail CI on findings at or above high severity
codex-plugin-scanner ./my-plugin --fail-on-severity high

# Require Cisco skill scanning with a strict policy
codex-plugin-scanner ./my-plugin --cisco-skill-scan on --cisco-policy strict
```

## Example Output

```text
🔗 Codex Plugin Scanner v1.2.0
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

## CI And Automation

Add the scanner to a plugin repository CI job:

```yaml
- name: Install scanner
  run: pip install codex-plugin-scanner

- name: Scan plugin
  run: codex-plugin-scanner ./my-plugin --fail-on-severity high --format sarif --output codex-plugin-scanner.sarif
  continue-on-error: true
```

Local pre-commit style hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: codex-plugin-scanner
        name: Codex Plugin Scanner
        entry: codex-plugin-scanner
        language: system
        types: [directory]
        pass_filenames: false
        args: ["./"]
```

## GitHub Action

The scanner ships with a composite GitHub Action source bundle in [action/action.yml](action/action.yml).

GitHub Marketplace has two important constraints for actions:

- the published action must live in a dedicated public repository with a single root `action.yml`
- that repository cannot contain workflow files

Because the scanner repository itself contains CI and release workflows, the Marketplace listing should be published from a separate action-only repository. The scanner release workflow now emits a root-ready bundle zip for that repository on every tagged release.

The source README for that dedicated action repository lives in [action/README.md](action/README.md), and the full publication guide lives in [docs/github-action-marketplace.md](docs/github-action-marketplace.md).

### Plugin Author Submission Flow

The action can also handle submission intake. A plugin repository can wire the scanner into CI so a passing scan opens or reuses a submission issue in [awesome-codex-plugins](https://github.com/hashgraph-online/awesome-codex-plugins).

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
        uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
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

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
ruff format --check src
pytest -q
python -m build
```

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

## Resources

- [OpenAI Codex Plugin Documentation](https://developers.openai.com/codex/plugins)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Cisco AI Skill Scanner](https://pypi.org/project/cisco-ai-skill-scanner/)
- [HOL GitHub Organization](https://github.com/hashgraph-online)

## License

Apache-2.0
