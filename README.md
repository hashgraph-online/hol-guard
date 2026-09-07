# HOL Guard: Open-Source Antivirus for AI Agents

<!-- mcp-name: io.github.hashgraph-online/hol-guard -->

[![HOL Guard Version](https://img.shields.io/pypi/v/hol-guard.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/hol-guard/)
[![Plugin Scanner Version](https://img.shields.io/pypi/v/plugin-scanner.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/plugin-scanner/)
[![HOL Guard Downloads](https://img.shields.io/pypi/dm/hol-guard?logo=pypi&logoColor=white)](https://pypi.org/project/hol-guard/)
[![Plugin Scanner Downloads](https://img.shields.io/pypi/dm/plugin-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/plugin-scanner/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#install-hol-guard)
[![CI](https://img.shields.io/github/actions/workflow/status/hashgraph-online/hol-guard/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/hashgraph-online/hol-guard/actions/workflows/ci.yml)
[![Publish](https://img.shields.io/github/actions/workflow/status/hashgraph-online/hol-guard/publish.yml?branch=main&label=Publish&logo=githubactions&logoColor=white)](https://github.com/hashgraph-online/hol-guard/actions/workflows/publish.yml)
[![Container Image](https://img.shields.io/badge/ghcr-hol--guard-2496ED?logo=docker&logoColor=white)](https://github.com/hashgraph-online/hol-guard/pkgs/container/hol-guard)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hashgraph-online/hol-guard/badge)](https://scorecard.dev/viewer/?uri=github.com/hashgraph-online/hol-guard)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/hashgraph-online/hol-guard?style=social)](https://github.com/hashgraph-online/hol-guard/stargazers)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-D7FF64.svg)](https://github.com/astral-sh/ruff)

| ![HOL whole dark logo](https://hol.org/brand/Logo_Whole_Dark.png) | **Stop risky AI actions before they compromise your machine.** HOL Guard is a local-first security layer for AI agents, tools, plugins, skills, MCP servers, and package installs.<br><br>[Install HOL Guard](https://hol.org/guard/activate)<br>[Read the documentation](https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/get-started.md)<br>[PyPI Package (`hol-guard`)](https://pypi.org/project/hol-guard/)<br>[Report an Issue](https://github.com/hashgraph-online/hol-guard/issues) |
| :--- | :--- |

HOL Guard reviews agent actions before they run: shell commands, file access, package installs, and MCP tool calls. It detects secret exposure, destructive operations, prompt injection, and supply-chain risks, then allows, blocks, or requests approval according to your policy.

Run it locally without an account. Use the CLI and local dashboard to manage protection, resolve approvals, and inspect decision history. Optional [Guard Cloud](docs/guard/local-vs-cloud.md) adds shared history, team policy, and fleet management.

[Get started](#install-hol-guard) · [Supported agents](#supported-ai-agents) · [Plugin scanner](#plugin-scanner) · [Documentation](#documentation) · [Contributing](#development)

## Install HOL Guard

Requires Python 3.10 or newer and [pipx](https://pipx.pypa.io/stable/installation/).

```bash
pipx install hol-guard
hol-guard init
```

The first-run wizard discovers supported agents and walks you through protection setup. It asks before each setup change, including opening the dashboard, installing agent integrations, and connecting optional cloud services.

Check your installation:

```bash
hol-guard --version
hol-guard status
```

To update an existing installation:

```bash
hol-guard update
```

For manual setup, see the [installation guide](docs/guard/get-started.md). Release details and prereleases are on the [releases page](https://github.com/hashgraph-online/hol-guard/releases).

## What HOL Guard Protects

| Surface | Protection |
| :--- | :--- |
| **Shell commands and file access** | Reviews destructive operations, sensitive file access, credential exposure, and suspicious outbound commands. |
| **Package installs** | Evaluates supported package-manager operations against supply-chain intelligence before installation. |
| **Plugins, skills, and agent configuration** | Inventories local artifacts and reviews new or changed tools before launch. |
| **MCP servers and tools** | Inspects server configuration and reviews tool calls through supported hooks and managed proxies. |
| **Prompts and tool results** | Screens supported events for prompt injection and sensitive content. |
| **Approvals and evidence** | Routes decisions to native prompts or the approval center, and records local receipts for review. |

Guard connects through native agent hooks, managed MCP proxies, and launch integrations. Coverage depends on the events each agent exposes; the [support matrix](docs/guard/harness-support.md) documents enforcement, approval delivery, and failure behavior per integration.

## Supported AI Agents

Codex, Claude Code, GitHub Copilot CLI, Cursor, Cline, Gemini CLI, Grok, Hermes, Kimi Code, Pi, oh-my-pi, OpenClaw, OpenCode, Antigravity, and ZCode.

For example, to set up Codex explicitly:

```bash
hol-guard install codex
hol-guard run codex --dry-run
hol-guard run codex
```

The dry run records the current artifact state before launch. For Codex, Guard installs native pre-tool hooks and refuses a managed launch if those hooks are missing or disabled.

[Agent support matrix](docs/guard/harness-support.md) · [Troubleshooting](docs/guard/troubleshooting.md)

## Everyday Use

| Task | Command |
| :--- | :--- |
| Check protection status | `hol-guard status` |
| Diagnose an agent integration | `hol-guard doctor codex` |
| Inspect changes before launch | `hol-guard diff codex` |
| Review pending approvals | `hol-guard approvals` |
| Approve or deny a request | `hol-guard approvals approve <request-id>` / `hol-guard approvals deny <request-id>` |
| Read decision history | `hol-guard receipts` |
| List tracked artifacts | `hol-guard inventory` |
| Export an AI bill of materials | `hol-guard abom --format json` |
| Scan workspace dependencies | `hol-guard supply-chain scan` |
| Connect optional cloud sync | `hol-guard connect` |

### Understand a paused command

Inspect the command's classification and matching rules:

```bash
hol-guard command test 'rm -rf ./build'
hol-guard command explain 'git clean -ndx'
hol-guard command extensions command.git --json
```

`command test` and `command explain` inspect the command without executing it or creating an approval. Use `hol-guard approvals` to resolve a pending request and `hol-guard receipts` to review the recorded decision.

The [Extension directory](docs/guard/extensions/README.md) lists command coverage generated from the runtime registry. External contributions require explicit opt-in; required core protections remain enabled. To add coverage, follow the [Extension contribution guide](docs/guard/extensions/contributing.md).

### Check a package

```bash
hol-guard supply-chain sync
hol-guard supply-chain scan
hol-guard supply-chain explain minimist@1.2.5 --ecosystem npm
```

The package verdict includes the available advisory evidence and ecosystem coverage. See the [get-started guide](docs/guard/get-started.md) for package-manager interception and the [remediation guide](docs/guard/remediation.md) for handling false positives.

## Plugin Scanner

This repository also ships `plugin-scanner`, a CLI for maintainers who want security and quality checks before publishing agent plugins, skills, and MCP integrations.

```bash
pipx install plugin-scanner
plugin-scanner scan .
plugin-scanner lint .
plugin-scanner verify .
```

| Command | Purpose |
| :--- | :--- |
| `scan` | Security findings and a quality report across detected package surfaces. |
| `lint` | Rule-level authoring feedback. |
| `verify` | Install-surface and runtime readiness checks. |
| `submit` | A submission artifact for one plugin package. |
| `doctor` | Component diagnostics and troubleshooting bundles. |

The scanner detects Codex, Claude Code, DeepSeek Harness, Gemini CLI, Kimi Code, and OpenCode package formats. Use `plugin-scanner --list-ecosystems` to list them or `--ecosystem` to select one. At a Codex marketplace root, it discovers local plugin entries automatically.

Checks cover manifests, secrets, MCP transport and command configuration, approval defaults, skills, dependency lockfiles, and GitHub Actions permissions. Optional Cisco integrations add skill and MCP analysis. Reports support text, JSON, Markdown, and SARIF.

```bash
plugin-scanner scan . --format sarif --output plugin-scanner.sarif
plugin-scanner scan . --fail-on-severity high
```

Quality grades use the checks applicable to each package. Trust scoring has separate provenance and weights; see the [skill](docs/trust/skill-trust-local.md), [MCP](docs/trust/mcp-trust-draft.md), and [plugin](docs/trust/plugin-trust-draft.md) scoring references.

### GitHub Actions

Add the scanner to a plugin repository:

```yaml
name: Plugin security
on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      - uses: hashgraph-online/ai-plugin-scanner-action@fdb49f9d85321a2ced2933301b395dd3c1ce9c8f # v1.2.631
        with:
          plugin_dir: "."
          min_score: 80
          fail_on_severity: high
```

See the [action documentation](https://github.com/hashgraph-online/ai-plugin-scanner-action) for SARIF uploads, submission workflows, and machine-readable outputs. The action source is maintained in [`action/`](action/).

### Optional Cisco analysis

The baseline packages work without Cisco dependencies. To add Cisco skill scanning, use Python 3.11 through 3.14 and install the extra in an isolated environment:

```bash
pipx install 'plugin-scanner[cisco]'
```

For Cisco MCP analysis, use the repository's [Docker image](Dockerfile) or the `cisco-mcp` dependency group:

```bash
uv sync --extra dev --extra cisco --group cisco-mcp --python 3.13
uv run plugin-scanner scan . --cisco-skill-scan on --cisco-mcp-scan on
```

The published `cisco` extra provides skill scanning; the separate `cisco-mcp` group supplies the MCP scanner. Dependency versions and Python constraints are maintained in [`pyproject.toml`](pyproject.toml).

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Get started](docs/guard/get-started.md) | Installation, manual setup, package protection, and common commands. |
| [Agent support](docs/guard/harness-support.md) | Integration coverage and approval behavior. |
| [Architecture](docs/guard/architecture.md) | Runtime components and decision flow. |
| [Policy specification](spec/guard-policy/v1alpha1/README.md) | GuardPolicy document format. |
| [Policy recipes](docs/guard/policy-recipes.md) | Configuration examples for common workflows. |
| [Extensions](docs/guard/extensions/README.md) | Built-in command rules and contribution guidance. |
| [Local vs. cloud](docs/guard/local-vs-cloud.md) | Local capabilities and optional cloud services. |
| [Troubleshooting](docs/guard/troubleshooting.md) | Diagnosis and recovery. |
| [Security](SECURITY.md) | Vulnerability reporting and disclosure policy. |

## Development

Clone the repository and install the development dependencies with uv:

```bash
git clone https://github.com/hashgraph-online/hol-guard.git
cd hol-guard
uv sync --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest --tb=short
uv build
```

For optional Cisco coverage, use the dependency group command above. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements and the [testing matrix](docs/guard/testing-matrix.md) for integration tests.

## Community

Maintained by [Hashgraph Online](https://github.com/hashgraph-online).

- [Report a bug or request a feature](https://github.com/hashgraph-online/hol-guard/issues)
- [Browse releases](https://github.com/hashgraph-online/hol-guard/releases)
- [Explore the plugin security dataset](https://huggingface.co/datasets/HashgraphOnline/hol-plugin-security)

## License

Licensed under [Apache-2.0](LICENSE).
