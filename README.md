# 🔗 Codex Plugin Scanner

[![PyPI version](https://img.shields.io/pypi/v/codex-plugin-scanner.svg)](https://pypi.org/project/codex-plugin-scanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/codex-plugin-scanner.svg)](https://pypi.org/project/codex-plugin-scanner/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/codex-plugin-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/codex-plugin-scanner)

A security, publishability, and security-ops scanner for [Codex plugins](https://developers.openai.com/codex/plugins). It scores the applicable plugin surface from 0-100, emits structured findings, validates install-surface metadata, hardens MCP transport expectations, and can run Cisco's `skill-scanner` against plugin skills for deeper analysis.

## What's New in v1.2.0

- Publishability checks for Codex `interface` metadata, assets, and HTTPS links.
- MCP transport hardening for remote `.mcp.json` endpoints.
- A new `Operational Security` category for GitHub Actions pinning, privileged workflow patterns, Dependabot, and lockfile hygiene.

## Installation

```bash
pip install codex-plugin-scanner
```

To enable Cisco-backed skill scanning:

```bash
pip install "codex-plugin-scanner[cisco]"
```

Or run directly without installing:

```bash
pipx run codex-plugin-scanner ./my-plugin
```

## Usage

```bash
# Scan a plugin directory
codex-plugin-scanner ./my-plugin

# Output as JSON
codex-plugin-scanner ./my-plugin --json

# Write a SARIF report for GitHub code scanning
codex-plugin-scanner ./my-plugin --format sarif --output report.sarif

# Fail CI on high-severity findings
codex-plugin-scanner ./my-plugin --fail-on-severity high

# Require Cisco skill scanning with a strict policy
codex-plugin-scanner ./my-plugin --cisco-skill-scan on --cisco-policy strict
```

### Example Output

```
🔗 Codex Plugin Scanner v1.2.0
Scanning: ./my-plugin

── Manifest Validation (31/31) ──
  ✅ plugin.json exists                          +4
  ✅ Valid JSON                                  +4
  ✅ Required fields present                     +5
  ✅ Version follows semver                      +3
  ✅ Name is kebab-case                          +2
  ✅ Recommended metadata present                +4
  ✅ Interface metadata complete if declared     +3
  ✅ Interface links and assets valid if declared +3
  ✅ Declared paths are safe                     +3

── Security (16/16) ──
  ✅ SECURITY.md found                           +3
  ✅ LICENSE found                               +3
  ✅ No hardcoded secrets                        +7
  ✅ No dangerous MCP commands                   +0
  ✅ MCP remote transports are hardened          +0
  ✅ No approval bypass defaults                 +3

── Operational Security (0/0) ──
  ✅ Third-party GitHub Actions pinned to SHAs   +0
  ✅ No write-all GitHub Actions permissions     +0
  ✅ No privileged untrusted checkout patterns   +0
  ✅ Dependabot configured for automation surfaces +0
  ✅ Dependency manifests have lockfiles         +0

── Skill Security (15/15) ──
  ✅ Cisco skill scan completed                  +3
  ✅ No elevated Cisco skill findings            +8
  ✅ Skills analyzable                           +4

Findings: critical:0, high:0, medium:0, low:0, info:0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Score: 100/100 (A - Excellent)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Optional surfaces such as `marketplace.json`, `.mcp.json`, and plugin skills are treated as not-applicable when they are not present. The final score is normalized over the applicable maximum so plugins are not rewarded or penalized for surfaces they do not expose.

## Checks

| Category | Max Points | Checks |
|----------|-----------|--------|
| Manifest Validation | 31 | plugin.json, required fields, semver, kebab-case, recommended metadata, interface metadata, interface assets, safe declared paths |
| Security | 24 | SECURITY.md, LICENSE, no hardcoded secrets, no dangerous MCP commands, MCP remote transport hardening, no approval bypass defaults |
| Operational Security | 20 | GitHub Actions SHA pinning, no `write-all`, no privileged untrusted checkout, Dependabot, dependency lockfiles |
| Best Practices | 15 | README.md, skills directory, SKILL.md frontmatter, no committed `.env`, `.codexignore` |
| Marketplace | 15 | marketplace.json validity, policy fields, safe source paths |
| Skill Security | 15 | Cisco scan availability, elevated skill findings, analyzability |
| Code Quality | 10 | no eval/Function, no shell injection |

### Grade Scale

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Excellent |
| 80-89 | B | Good |
| 70-79 | C | Acceptable |
| 60-69 | D | Needs Improvement |
| 0-59 | F | Failing |

## Security Checks

The scanner detects:

- **Hardcoded secrets**: AWS keys, GitHub tokens, OpenAI keys, Slack tokens, GitLab tokens, generic password/secret/token patterns
- **Dangerous MCP commands**: `rm -rf`, `sudo`, `curl|sh`, `wget|sh`, `eval`, `exec`, `powershell -c`
- **Insecure MCP remotes**: non-HTTPS remote endpoints and non-loopback HTTP MCP transports
- **Risky Codex defaults**: approval bypass and unrestricted sandbox defaults in plugin-shipped config/docs
- **Shell injection**: template literals with unsanitized interpolation in exec/spawn calls
- **Unsafe code**: `eval()` and `new Function()` usage
- **Cisco skill threats**: policy violations and risky behaviors detected by Cisco `skill-scanner`
- **Workflow hardening gaps**: unpinned third-party actions, `write-all`, privileged untrusted checkouts, missing Dependabot, missing lockfiles

## Report Formats

- `text`: human-readable terminal summary with findings and category scores
- `json`: structured findings, integration status, and per-check details
- `markdown`: review-ready report for issues and pull requests
- `sarif`: GitHub code scanning compatible output

## Use as a GitHub Action

Add to your plugin's CI:

```yaml
- name: Install scanner
  run: pip install codex-plugin-scanner
- name: Scan plugin
  run: codex-plugin-scanner ./my-plugin --fail-on-severity high --format sarif --output codex-plugin-scanner.sarif
```

## Use as a pre-commit hook

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

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE) - Hashgraph Online
