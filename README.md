# 🔗 Codex Plugin Scanner

[![PyPI version](https://img.shields.io/pypi/v/codex-plugin-scanner.svg)](https://pypi.org/project/codex-plugin-scanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/codex-plugin-scanner.svg)](https://pypi.org/project/codex-plugin-scanner/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/codex-plugin-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/codex-plugin-scanner)

A security and best-practices scanner for [Codex CLI plugins](https://developers.openai.com/codex/plugins). Scans plugin directories and outputs a score from 0-100.

## Installation

```bash
pip install codex-plugin-scanner
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

# Write report to file
codex-plugin-scanner ./my-plugin --output report.json
```

### Example Output

```
🔗 Codex Plugin Scanner v1.0.0
Scanning: ./my-plugin

── Manifest Validation (25/25) ──
  ✅ plugin.json exists                          +5
  ✅ Valid JSON                                   +5
  ✅ Required fields present                      +8
  ✅ Version follows semver                       +4
  ✅ Name is kebab-case                           +3

── Security (30/30) ──
  ✅ SECURITY.md found                           +5
  ✅ LICENSE found (Apache-2.0)                  +5
  ✅ No hardcoded secrets detected               +10
  ✅ No dangerous MCP commands                   +10

── Best Practices (25/25) ──
  ✅ README.md found                             +5
  ✅ Skills directory exists if declared          +5
  ✅ SKILL.md frontmatter                        +5
  ✅ No .env files committed                     +5
  ✅ .codexignore found                          +5

── Marketplace (10/10) ──
  ✅ marketplace.json valid                      +5
  ✅ Policy fields present                       +5

── Code Quality (10/10) ──
  ✅ No eval or Function constructor             +5
  ✅ No shell injection patterns                 +5

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Final Score: 100/100 (A - Excellent)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Scoring Breakdown

| Category | Max Points | Checks |
|----------|-----------|--------|
| Manifest Validation | 25 | plugin.json exists, valid JSON, required fields, semver version, kebab-case name |
| Security | 30 | SECURITY.md, LICENSE, no hardcoded secrets, no dangerous MCP commands |
| Best Practices | 25 | README.md, skills directory, SKILL.md frontmatter, no .env files, .codexignore |
| Marketplace | 10 | marketplace.json valid, policy fields present |
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
- **Shell injection**: template literals with unsanitized interpolation in exec/spawn calls
- **Unsafe code**: `eval()` and `new Function()` usage

## Use as a GitHub Action

Add to your plugin's CI:

```yaml
- name: Install scanner
  run: pip install codex-plugin-scanner
- name: Scan plugin
  run: codex-plugin-scanner ./my-plugin
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
