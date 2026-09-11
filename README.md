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

[Get started](#install-hol-guard) · [Supported agents](#supported-ai-agents) · [Plugin scanner](#plugin-scanner) · [Documentation](#documentation) · [Contribute an extension](#contribute-a-new-extension) · [Development](#development)

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

<a id="guard-operations"></a>

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

<a id="guard-troubleshooting"></a>
<a id="inspect-command-protection-without-running-it"></a>

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

<a id="scanner-quickstart"></a>
<a id="choose-the-right-package"></a>

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

<a id="ci-and-automation"></a>

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

<a id="install-the-package-you-need"></a>
<a id="resolver-safe-cisco-extra"></a>

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

## Ecosystem Support

| Ecosystem | Detection surfaces |
| :--- | :--- |
| Codex | `.codex-plugin/plugin.json`, `marketplace.json`, `.agents/plugins/marketplace.json` |
| Claude Code | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` |
| DeepSeek Harness | `package.json` with `dsh.bundle`, declared patches, and Cordis `apply(ctx)` exports, or `dsh.bundle.mode` set to `"patch"` for patch-only bundles |
| Gemini CLI | `gemini-extension.json`, `commands/**/*.toml` |
| Kimi Code | `kimi.plugin.json`, `.kimi-plugin/plugin.json`, declared skills, agents, commands, prompts, and MCP servers |
| OpenCode | `opencode.json`, `opencode.jsonc`, `.opencode/commands`, `.opencode/plugins` |

Use `--ecosystem auto` to detect supported packages in a repository, or select an ecosystem explicitly:

```bash
plugin-scanner scan ./plugins-repo --ecosystem claude
plugin-scanner scan ./dsh-plugin --ecosystem deepseek-harness
```

## What The Scanner Checks

| Category | Coverage |
| :--- | :--- |
| Manifest validation | Required fields, versions, declared paths, interface metadata, links, and assets. |
| Security | Hardcoded secrets, unsafe MCP commands and transports, and risky approval defaults. |
| Operational security | GitHub Actions permissions and pinned dependencies, privileged checkout patterns, Dependabot, and lockfiles. |
| Plugin packaging | README and license files, skill frontmatter, ignore rules, and accidentally committed environment files. |
| Marketplace | Manifest validity, local package discovery, and safe source paths. |
| Skill and MCP analysis | Analyzer availability, findings, and analyzability from optional Cisco integrations. |
| Code quality | Dynamic code execution and shell-injection patterns. |

## How Trust Scoring Works

Plugin Scanner reports a quality grade alongside trust provenance. Quality scores are normalized across applicable checks, so optional surfaces do not inflate a package's grade.

Skill trust uses the HCS-28 baseline adapter IDs, weights, and denominator rules. MCP and Codex plugin trust use explicit adapters, weights, and contribution modes documented in the local specifications:

- [Skill Trust Local Draft](docs/trust/skill-trust-local.md)
- [MCP Trust Draft](docs/trust/mcp-trust-draft.md)
- [Codex Plugin Trust Draft](docs/trust/plugin-trust-draft.md)

<a id="quality-suite-commands"></a>

For parseable Python files, the `eval` check inspects syntax: bare builtin references,
`builtins.eval` (including import aliases), and `.eval(...)` calls with arguments
remain findings. A no-argument method call such as PyTorch's
[`Module.eval()`](https://docs.pytorch.org/docs/stable/generated/torch.nn.Module.html#torch.nn.Module.eval)
does not by itself indicate dynamic code execution. Python comments and string
literals are not treated as `eval` calls; expressions inside f-strings are inspected.
If Python parsing fails, the conservative text check remains in effect. JavaScript
and TypeScript checks are unchanged. This rule is a heuristic, not type inference
or a proof that an arbitrary method implementation is safe.

## CLI Usage

```bash
# Structured security report
plugin-scanner scan ./my-plugin --format json --profile public-marketplace

# Inspect authoring rules
plugin-scanner lint ./my-plugin --list-rules
plugin-scanner lint ./my-plugin --explain README_MISSING

# Apply supported mechanical fixes
plugin-scanner lint ./my-plugin --fix --profile strict-security

# Verify package readiness; --online permits live probes
plugin-scanner verify ./my-plugin --format json
plugin-scanner verify ./my-plugin --online --format text

# Generate a submission artifact for one plugin
plugin-scanner submit ./my-plugin --profile public-marketplace --attest dist/plugin-quality.json

# Collect component diagnostics
plugin-scanner doctor ./my-plugin --component mcp --bundle dist/doctor.zip
```

For a repository marketplace, `scan`, `lint`, `verify`, and `doctor` can target the root. `submit` targets one plugin package.

## Codex Spec Alignment

The scanner recognizes Codex plugin manifests, interface metadata, declared assets, and marketplace packages:

- Local manifest paths use `./` prefixes; `lint --fix` preserves or adds them.
- `.agents/plugins/marketplace.json` is the preferred marketplace location, with root `marketplace.json` supported for compatibility.
- Interface validation checks declared links and assets without requiring an undocumented `type` field.
- `verify --online` checks HTTP remote reachability. Stdio server execution is skipped for manual review.

See the [Codex plugin documentation](https://developers.openai.com/codex/plugins) and [Model Context Protocol specification](https://modelcontextprotocol.io) for upstream formats.

## Config + Baseline Example

Configure the scanner in `.plugin-scanner.toml`:

```toml
[scanner]
profile = "public-marketplace"
baseline_file = "baseline.txt"
ignore_paths = ["tests/*", "fixtures/*"]

[rules]
disabled = ["README_MISSING"]
severity_overrides = { CODEXIGNORE_MISSING = "low" }
```

The GitHub Action requires `trust_repository_policy: true` before repository-owned configuration and baselines can change its verdict. Enable that option only for policy you intend the workflow to trust.

## Report Formats

| Format | Use |
| :--- | :--- |
| `text` | Terminal summaries with category totals and findings. |
| `json` | Structured reports for scripts and integrations. |
| `markdown` | Review-ready reports for pull requests and issues. |
| `sarif` | GitHub code scanning and security automation. |

## GitHub Action

The [AI Plugin Scanner Action](https://github.com/hashgraph-online/ai-plugin-scanner-action) supports security gates, SARIF uploads, submission intake, and registry payloads. Its source lives in [`action/`](action/), and the [publication workflow](.github/workflows/publish-action-repo.yml) distributes the action bundle.

The legacy [HOL Codex Plugin Scanner Action](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action) remains available for existing workflows.

### Plugin Author Submission Flow

Use `submission_enabled: true` to open or reuse a submission issue when a plugin meets the configured threshold. `submission_token` must have permission to create issues in the target submission repository. The action emits submission status and issue URLs as outputs.

See the [action's input reference](action/action.yml) for `submission_score_threshold`, `submission_token`, and the target repository options.

### Registry Payload For Plugin Ecosystem Automation

Set `registry_payload_output` to write a machine-readable payload for a registry or badge pipeline. The action also exposes `score`, `grade`, `grade_label`, `max_severity`, and `findings_total` outputs and can write a job summary.

The [HOL Registry Broker plugin](https://github.com/hashgraph-online/registry-broker-codex-plugin) is an example of an agent plugin in the [HOL Plugin Registry](https://hol.org/registry/plugins). Its [registry listing](https://hol.org/registry/plugins/hol%2Fregistry-broker-codex-plugin) provides current trust information.

## Why HOL Guard

AI agents can run commands, install dependencies, read files, and call external tools within one session. HOL Guard reviews those actions at supported execution points and keeps the policy decision, approval request, and receipt together.

Use it for AI agent security on a developer machine, MCP security around connected tools, and supply-chain checks for packages and plugins. Teams can add Guard Cloud for shared approvals and policy management while retaining local protection.

## Frequently Asked Questions

### What is HOL Guard?

HOL Guard is open-source antivirus and runtime protection for AI agents. It reviews supported tool calls, shell commands, file access, and package operations for risks such as secret exposure, prompt injection, destructive actions, and malicious dependencies.

### Does HOL Guard work without a cloud account?

Yes. Local protection, CLI commands, approvals, and receipts work without signing in. Guard Cloud is optional and adds synchronized evidence, team controls, and fleet visibility. See [Local Guard vs. Guard Cloud](docs/guard/local-vs-cloud.md) for the feature boundary.

### Which AI agents does HOL Guard support?

Guard includes adapters for Codex, Claude Code, GitHub Copilot CLI, Cursor, Cline, Gemini CLI, Grok, Hermes, Kimi Code, Pi, oh-my-pi, OpenClaw, OpenCode, Antigravity, and ZCode. The [support matrix](docs/guard/harness-support.md) explains which events and enforcement paths each adapter supports.

### What is the difference between HOL Guard and Plugin Scanner?

Install `hol-guard` to protect agent activity on your machine. Install `plugin-scanner` to inspect plugin packages and enforce security and quality checks in CI. This repository builds and publishes both distributions.

### How does HOL Guard protect MCP servers?

Guard inspects MCP server configuration and reviews supported MCP tool calls through agent hooks and managed proxies. Plugin Scanner checks MCP configuration and HTTP remote reachability; optional Cisco MCP analysis adds static security findings.

### Why did Guard pause my command?

The action may need approval under your active policy, or its tools or artifacts may have changed. Start with `hol-guard approvals`, inspect the command with `hol-guard command explain '<command>'`, and use `hol-guard receipts` to review the recorded decision.

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Get started](docs/guard/get-started.md) | Installation, manual setup, package protection, and common commands. |
| [Agent support](docs/guard/harness-support.md) | Integration coverage and approval behavior. |
| [Architecture](docs/guard/architecture.md) | Runtime components and decision flow. |
| [Policy specification](spec/guard-policy/v1alpha1/README.md) | GuardPolicy document format. |
| [Policy recipes](docs/guard/policy-recipes.md) | Configuration examples for common workflows. |
| [Extensions](docs/guard/extensions/README.md) | Built-in command rules and contribution guidance. |
| [Contribute an extension](#contribute-a-new-extension) | Generate, review, integrate, and test a new extension with the CLI. |
| [Local vs. cloud](docs/guard/local-vs-cloud.md) | Local capabilities and optional cloud services. |
| [Troubleshooting](docs/guard/troubleshooting.md) | Diagnosis and recovery. |
| [Security](SECURITY.md) | Vulnerability reporting and disclosure policy. |

## Contribute a New Extension

Use the **Extension Builder CLI** to turn exported command metadata or an MCP tool inventory into contribution files and tests. It works offline: it reads the export without importing or running the target tool.

**1. Propose the coverage.** Check the [Extension directory](docs/guard/extensions/README.md) for existing coverage. For a new capability, open an [Extension proposal](https://github.com/hashgraph-online/hol-guard/issues/new?template=command-extension-proposal.yml) with the proposed `command.<name>` ID, supported operations, destructive examples, safe counterparts, and upstream references. Extend an existing extension when it already owns the operation.

Follow the [development setup](#development), then run the examples below from your HOL Guard checkout. `uv run --no-sync` uses that checkout's installed development version.

**2. Generate a contribution kit.** This example uses the checked-in, synthetic `samplectl` inventory. For your own contribution, replace the input and metadata with your tool's export and public publisher details.

```bash
uv run --no-sync hol-guard extensions generate --from cli \
  --input docs/guard/extension-builder/examples/cli-surface.json \
  --slug samplectl --executable samplectl --name 'Sample CLI' \
  --publisher community.example --publisher-name 'Example Maintainer' \
  --homepage https://example.test/samplectl \
  --upstream-version 1.0.0 --output samplectl-kit

uv run --no-sync hol-guard extensions validate samplectl-kit
```

The output directory must be new, with an existing parent directory. The kit includes `discovery.json`, `review.json`, `report.json`, contribution metadata, a native detector, generated tests, and a file manifest.

Other inputs: `--from help` reads saved command help; `--from click` reads a Click `Context.to_info_dict()` export; `--from oclif` reads `oclif.manifest.json`; `--from mcp` reads a complete exported `tools/list` result; and `--from snapshot` replays `discovery.json`. The `cli` example above uses normalized `guard.cli-surface.v1` JSON.

For MCP contributions, the generator uses `--launcher` and `--package` instead of `--executable`. See the [MCP kit example](docs/guard/extension-builder/README.md#generate-an-mcp-kit) for a complete command and pagination requirements.

**3. Review the operations and regenerate.** Read `report.json` and compare the discovered operations with the upstream implementation. Copy the review file before editing:

```bash
cp samplectl-kit/review.json samplectl-review.json
```

Edit `samplectl-review.json`, keeping its discovery binding and operation IDs intact. CLI operations use `review` or `block`; the root operation stays `review`. Set `reviewed: true` for entries you have assessed, with rationale and a public HTTPS evidence reference. Add `safeArgv` only for exact, verified safe invocations. The [review format](docs/guard/extension-builder/README.md#review-and-recompile) includes a complete entry example.

Recompile from the saved snapshot rather than editing generated detectors or manifests:

```bash
uv run --no-sync hol-guard extensions generate --from snapshot \
  --input samplectl-kit/discovery.json \
  --review samplectl-review.json --output samplectl-reviewed

uv run --no-sync hol-guard extensions validate samplectl-reviewed
uv run --no-sync hol-guard extensions diff samplectl-kit samplectl-reviewed
```

`diff` exits `0` for equal kits and `1` when valid kits differ. If the upstream export changes, generate and review a new snapshot.

**4. Preview and apply the integration.** On your contribution branch, preview the changes to the current checkout:

```bash
uv run --no-sync hol-guard extensions apply samplectl-reviewed --repo .
```

Inspect the listed paths and generated files. Copy the printed plan digest into the following command before running it:

```bash
uv run --no-sync hol-guard extensions apply samplectl-reviewed --repo . \
  --expected-plan THE_PRINTED_PLAN_DIGEST \
  --write
```

The write applies the reviewed plan to contribution files, the external trust map, catalog registration, packaging, and authoring ownership records. Existing IDs or conflicting files stop integration for review.

**5. Test and submit a pull request.** For the `samplectl` example:

```bash
uv run --no-sync python scripts/release/stage_guard_cloud_review_artifacts.py
uv run --no-sync pytest -q tests/test_generated_cli_samplectl_extension.py
uv run --no-sync pytest -q \
  tests/test_guard_extension_contribution.py \
  tests/test_guard_extension_trust.py \
  tests/test_guard_command_extension_registry.py
uv run --no-sync python scripts/render_command_extension_directory.py
uv run --no-sync python scripts/render_command_extension_directory.py --check
git diff --check
```

Use your generated test filename for a different slug. Add cases for destructive operations, safe previews, aliases, reordered flags, quoting, malformed input, and compound commands. Run lint and formatting checks on changed Python files. Inspect the final diff, commit the integration and regenerated directory, and open a PR against `main` linking the proposal and test results. Include the generated authoring records; keep scratch kit directories and raw upstream exports out of the PR.

**Community contributions remain External and off by default.** Tests must prove they are inert until a local administrator enables them. Generating, applying, or merging a contribution does not activate it, and its detector cannot weaken Guard's required protections.

[Full builder reference](docs/guard/extension-builder/README.md) · [Contribution review requirements](docs/guard/extensions/contributing.md) · [External extension contract](docs/guard/extension-contributions.md) · [Builder validation](docs/guard/extension-builder/VALIDATION.md)

<a id="quick-start-for-contributors"></a>

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

## Resources

- [HOL Plugin Registry](https://hol.org/registry/plugins)
- [HOL Plugin Security dataset on Hugging Face](https://huggingface.co/datasets/HashgraphOnline/hol-plugin-security)
- [HOL Standards Documentation](https://hol.org/docs/standards)
- [OpenAI Codex Plugin Documentation](https://developers.openai.com/codex/plugins)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- [Cisco AI Skill Scanner](https://pypi.org/project/cisco-ai-skill-scanner/)
- [Cisco AI MCP Scanner](https://pypi.org/project/cisco-ai-mcp-scanner/)
- [HOL GitHub Organization](https://github.com/hashgraph-online)

## Community

Maintained by [Hashgraph Online](https://github.com/hashgraph-online).

- [Report a bug or request a feature](https://github.com/hashgraph-online/hol-guard/issues)
- [Browse releases](https://github.com/hashgraph-online/hol-guard/releases)
- [Explore the plugin security dataset](https://huggingface.co/datasets/HashgraphOnline/hol-plugin-security)

## License

Licensed under [Apache-2.0](LICENSE).
