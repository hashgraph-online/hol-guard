# HOL Codex Plugin Scanner

[![PyPI Version](https://img.shields.io/pypi/v/codex-plugin-scanner.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/codex-plugin-scanner/)
[![Python Versions](https://img.shields.io/pypi/pyversions/codex-plugin-scanner)](https://pypi.org/project/codex-plugin-scanner/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/codex-plugin-scanner)](https://pypistats.org/packages/codex-plugin-scanner)
[![CI](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml)
[![Publish](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/publish.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/publish.yml)
[![Container Image](https://img.shields.io/badge/ghcr-codex--plugin--scanner-2496ED?logo=docker&logoColor=white)](https://github.com/hashgraph-online/codex-plugin-scanner/pkgs/container/codex-plugin-scanner)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/codex-plugin-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/codex-plugin-scanner)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/hashgraph-online/codex-plugin-scanner?style=social)](https://github.com/hashgraph-online/codex-plugin-scanner/stargazers)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-D7FF64.svg)](https://github.com/astral-sh/ruff)

| ![](https://raw.githubusercontent.com/hashgraph-online/standards-sdk-py/main/Hashgraph-Online.png) | **The default CI gate for Codex plugins**. Lint locally, verify in CI, and ship publish-ready bundles for manifests, skills, MCP, and marketplace metadata.<br><br>Use this after [`$plugin-creator`](https://developers.openai.com/codex/plugins) and before publishing, review, or distribution.<br><br>[PyPI Package](https://pypi.org/project/codex-plugin-scanner/)<br>[HOL Plugin Registry](https://hol.org/registry/plugins)<br>[HOL GitHub Organization](https://github.com/hashgraph-online)<br>[Report an Issue](https://github.com/hashgraph-online/codex-plugin-scanner/issues) |
| :--- | :--- |

## Start In 30 Seconds

```bash
# Local preflight after scaffolding with $plugin-creator
pipx run codex-plugin-scanner lint .
pipx run codex-plugin-scanner verify .
```

```yaml
# GitHub Actions PR gate
- name: Codex plugin quality gate
  uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    fail_on_severity: high
    min_score: 80
```

If your repository uses a Codex marketplace root like `.agents/plugins/marketplace.json`, keep `plugin_dir: "."`. The scanner will discover local `./plugins/...` entries automatically, scan each local plugin manifest, and skip remote marketplace entries instead of treating the repo root as a single plugin.

## Use After `$plugin-creator`

`codex-plugin-scanner` is designed as the quality gate between plugin creation and distribution:

1. Scaffold with `$plugin-creator`.
2. Run `lint` locally to catch structure, metadata, and security issues early.
3. Run `verify` in CI to block regressions and enforce quality policy.
4. Ship or submit with confidence, backed by scanner artifacts and trust signals.

The score remains available as a trust and triage signal, but the primary workflow is **preflight + CI gating + publish readiness**.

## Trust Score Provenance

The scanner now emits explicit trust provenance alongside the quality grade:

- bundled skills inherit the live HOL broker adapter model from HCS-28 and HCS-26 alignment work
- MCP configuration trust is documented in a local draft spec
- top-level Codex plugin trust is documented in a local draft spec

Current local specs:

- [Skill Trust Local Draft](docs/trust/skill-trust-local.md)
- [MCP Trust Draft](docs/trust/mcp-trust-draft.md)
- [Codex Plugin Trust Draft](docs/trust/plugin-trust-draft.md)

This keeps the quality grade and the trust score separate. Signals like `SECURITY.md` are still visible, but their trust weight is now explicit instead of being inferred from raw category points.

## Quick Start For Contributors

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

The `cisco` extra installs the published `cisco-ai-skill-scanner` package from PyPI so the scanner remains publishable on PyPI and the optional Cisco analysis path works with standard package metadata.

You can also run the scanner without a local install:

```bash
pipx run codex-plugin-scanner ./my-plugin
```

Container-first environments can use the published image instead:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  ghcr.io/hashgraph-online/codex-plugin-scanner:<version> \
  scan /workspace --format text
```

## What The Scanner Covers

`codex-plugin-scanner` supports a full quality suite:

- `scan` for full-surface security and publishability analysis
- `lint` for rule-oriented authoring feedback
- `verify` for runtime and install-surface readiness checks
- `submit` for artifact-backed submission gating
- `doctor` for targeted diagnostics and troubleshooting bundles

The scanner evaluates only the surfaces a plugin actually exposes, then normalizes the final score across applicable checks. A plugin is not rewarded or penalized for optional surfaces it does not ship.

| Category | Max Points | Coverage |
| :--- | :--- | :--- |
| Manifest Validation | 31 | `plugin.json`, required fields, semver, kebab-case, recommended metadata, interface metadata, interface links and assets, safe declared paths |
| Security | 24 | `SECURITY.md`, `LICENSE`, hardcoded secret detection, dangerous MCP commands, MCP transport hardening, risky approval defaults |
| Operational Security | 20 | SHA-pinned GitHub Actions, `write-all`, privileged untrusted checkout patterns, Dependabot, dependency lockfiles |
| Best Practices | 15 | `README.md`, skills directory, `SKILL.md` frontmatter, committed `.env`, `.codexignore` |
| Marketplace | 15 | `.agents/plugins/marketplace.json` validity, legacy `marketplace.json` compatibility, policy fields, safe source paths |
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

## Quality Suite Commands

```bash
# Summary scan (legacy form still works)
codex-plugin-scanner scan ./my-plugin --format json --profile public-marketplace

# Scan a multi-plugin repo from the marketplace root
codex-plugin-scanner scan . --format json

# Rule-oriented lint (with optional mechanical fixes)
codex-plugin-scanner lint ./my-plugin --list-rules
codex-plugin-scanner lint ./my-plugin --explain README_MISSING
codex-plugin-scanner lint ./my-plugin --fix --profile strict-security

# Runtime readiness verification
codex-plugin-scanner verify ./my-plugin --format json
codex-plugin-scanner verify . --format json
codex-plugin-scanner verify ./my-plugin --online --format text

# Artifact-backed submission gate
codex-plugin-scanner submit ./my-plugin --profile public-marketplace --attest dist/plugin-quality.json

# Diagnostic bundle
codex-plugin-scanner doctor ./my-plugin --component mcp --bundle dist/doctor.zip
```

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
# .codex-plugin-scanner.toml
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
🔗 Codex Plugin Scanner v1.4.0
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
permissions:
  contents: read
  security-events: write

jobs:
  scan-plugin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
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

Because the scanner repository itself contains CI and release workflows, the Marketplace listing should be published from a separate action-only repository.

The dedicated action-repository guide now lives directly in [action/README.md](action/README.md).

### Automated Action Publication

The source repository can publish the GitHub Action automatically into a dedicated public action repository.

Configure:

- repository secret `ACTION_REPO_TOKEN`
  It should be a token that can create or update repositories and releases in the target repository.
- optional repository variable `ACTION_REPOSITORY`
  Defaults to `hashgraph-online/hol-codex-plugin-scanner-action`.

When a tagged release is published, [publish-action-repo.yml](./.github/workflows/publish-action-repo.yml) will:

- create the dedicated action repository if it does not already exist
- sync the root-ready `action.yml`, `README.md`, `LICENSE`, and `SECURITY.md`
- push the immutable release tag such as `v1.4.0`
- move the floating `v1` tag
- create or update the corresponding release in the action repository

GitHub Marketplace still requires the one-time listing publication step in the dedicated action repository UI, but after that this repository can keep the action repository current automatically.

### Plugin Author Submission Flow

The action can also handle submission intake. A plugin repository can wire the scanner into CI so a passing scan opens or reuses a submission issue in [awesome-codex-plugins](https://github.com/hashgraph-online/awesome-codex-plugins).

It also emits Codex-friendly machine outputs:

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

### Registry Payload For Codex Ecosystem Automation

If you want to feed the same scan into a registry, badge pipeline, or another Codex automation step, request a registry payload file directly from the action:

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
        uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          format: sarif
          output: codex-plugin-scanner.sarif
          registry_payload_output: codex-plugin-registry-payload.json

      - name: Show trust signals
        run: |
          echo "Score: ${{ steps.scan.outputs.score }}"
          echo "Grade: ${{ steps.scan.outputs.grade_label }}"
          echo "Max severity: ${{ steps.scan.outputs.max_severity }}"

      - name: Upload registry payload
        uses: actions/upload-artifact@v6
        with:
          name: codex-plugin-registry-payload
          path: ${{ steps.scan.outputs.registry_payload_path }}
```

The registry payload mirrors the submission data used by HOL ecosystem automation, so one scan can drive code scanning, review summaries, awesome-list intake, and registry trust ingestion.

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

## Example: HOL Registry Broker Plugin

The [HOL Registry Broker Codex Plugin](https://github.com/hashgraph-online/registry-broker-codex-plugin) bridges Codex plugins with the [HOL Universal Registry](https://hol.org/registry/plugins), providing agent discovery, trust signals, and verified identity on Hedera.

[![Registry Broker trust badge](https://img.shields.io/endpoint?url=https%3A%2F%2Fhol.org%2Fapi%2Fregistry%2Fbadges%2Fplugin%3Fslug%3Dhol%252Fregistry-broker-codex-plugin%26metric%3Dtrust%26style%3Dflat)](https://hol.org/registry/plugins/hol%2Fregistry-broker-codex-plugin)

HOL Registry scores: **Trust 80** / **Review 83** / **Enforce 74**

```text
🔗 Codex Plugin Scanner v1.4.0
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

## Resources

- [HOL Plugin Registry](https://hol.org/registry/plugins)
- [HOL Standards Documentation](https://hol.org/docs/standards)
- [OpenAI Codex Plugin Documentation](https://developers.openai.com/codex/plugins)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Cisco AI Skill Scanner](https://pypi.org/project/cisco-ai-skill-scanner/)
- [HOL GitHub Organization](https://github.com/hashgraph-online)

## License

Apache-2.0
