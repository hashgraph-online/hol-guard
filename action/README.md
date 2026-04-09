# AI Plugin Scanner GitHub Action

[![Latest Release](https://img.shields.io/github/v/release/hashgraph-online/ai-plugin-scanner-action?display_name=tag)](https://github.com/hashgraph-online/ai-plugin-scanner-action/releases/latest)
[![Canonical Repository](https://img.shields.io/badge/github-canonical_repo-0A84FF)](https://github.com/hashgraph-online/ai-plugin-scanner-action)
[![Source of Truth](https://img.shields.io/badge/source-ai--plugin--scanner-111827)](https://github.com/hashgraph-online/ai-plugin-scanner/tree/main/action)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/hashgraph-online/ai-plugin-scanner/blob/main/LICENSE)

| ![Hashgraph Online Logo](https://hol.org/brand/Logo_Whole_Dark.png) | Canonical GitHub Action repository for scanning AI plugin repositories across Codex, Claude, Gemini, and OpenCode ecosystems for security, publishability, runtime readiness, and trust signals. The action emits structured reports, SARIF, policy results, and submission metadata while staying aligned to the main scanner release train.<br><br>[Latest Release](https://github.com/hashgraph-online/ai-plugin-scanner-action/releases/latest)<br>[Canonical Repository](https://github.com/hashgraph-online/ai-plugin-scanner-action)<br>[Scanner Source of Truth](https://github.com/hashgraph-online/ai-plugin-scanner/tree/main/action)<br>[Report an Issue](https://github.com/hashgraph-online/ai-plugin-scanner/issues) |
| :--- | :--- |

Use `hashgraph-online/ai-plugin-scanner-action@v1` in new workflows. The legacy `hashgraph-online/hol-codex-plugin-scanner-action@v1` slug remains supported for compatibility.

The action installs the reviewed `plugin-scanner` release pinned by exact version and wheel SHA256, verifies its PyPI provenance against `hashgraph-online/ai-plugin-scanner`, and then runs locally by default for `scan`, `lint`, and offline `verify`. Live network probing and submission automation stay opt-in.

Advanced distribution paths are available when you need them:

- `install_source: local` is the explicit dogfood path for `uses: ./action` inside the source repo.
- `ghcr.io/hashgraph-online/ai-plugin-scanner` is the container distribution for enterprise runners that prefer a reviewed OCI image over runtime package installation.

## Usage

```yaml
- name: Scan AI Plugin Repository
  uses: hashgraph-online/ai-plugin-scanner-action@v1
  with:
    plugin_dir: "./my-plugin"
    min_score: 70
    fail_on_severity: high
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `plugin_dir` | Path to a single plugin directory or a repo marketplace root | `.` |
| `mode` | Execution mode: `scan`, `lint`, `verify`, or `submit` | `scan` |
| `format` | Output format: `text`, `json`, `markdown`, `sarif` | `text` |
| `output` | Write report to this file path | `""` |
| `profile` | Policy profile: `default`, `public-marketplace`, or `strict-security` | `default` |
| `config` | Optional path to a scanner config file such as `.plugin-scanner.toml` | `""` |
| `baseline` | Optional path to a baseline suppression file | `""` |
| `online` | Enable live network probing for `verify` mode | `false` |
| `upload_sarif` | Upload the generated SARIF report to GitHub code scanning when `mode: scan` | `false` |
| `sarif_category` | SARIF category used during GitHub code scanning upload | `ai-plugin-scanner` |
| `write_step_summary` | Write a concise markdown summary to the GitHub Actions job summary | `true` |
| `registry_payload_output` | Write a machine-readable plugin ecosystem payload JSON file for registry or awesome-list automation | `""` |
| `min_score` | Fail if score is below this threshold (0-100) | `0` |
| `fail_on_severity` | Fail on findings at or above this severity: `none`, `critical`, `high`, `medium`, `low`, `info` | `none` |
| `cisco_skill_scan` | Cisco skill-scanner mode: `auto`, `on`, `off` | `auto` |
| `cisco_policy` | Cisco policy preset: `permissive`, `balanced`, `strict` | `balanced` |
| `install_cisco` | Install the opt-in Cisco skill-scanner dependency used by this repo | `false` |
| `install_source` | Package install source: `pypi` for the reviewed release path, or `local` for source-repo dogfooding | `pypi` |
| `submission_enabled` | Open submission issues for awesome-list and registry automation when the plugin clears the submission threshold | `false` |
| `submission_score_threshold` | Minimum score required before a submission issue is created | `80` |
| `submission_repos` | Comma-separated GitHub repositories that should receive the submission issue | `hashgraph-online/awesome-codex-plugins` |
| `submission_token` | Required when `submission_enabled` is `true`; use a token with `issues:write` access to the submission repositories | `""` |
| `submission_labels` | Comma-separated labels to apply when creating submission issues | `plugin-submission` |
| `submission_category` | Listing category included in the submission issue body | `Community Plugins` |
| `submission_plugin_name` | Override the plugin name used in the submission issue | `""` |
| `submission_plugin_url` | Override the plugin repository URL used in the submission issue | `""` |
| `submission_plugin_description` | Override the plugin description used in the submission issue | `""` |
| `submission_author` | Override the plugin author used in the submission issue | `""` |
| `pr_comment` | PR comment mode: `auto`, `always`, or `off` | `auto` |
| `pr_comment_style` | PR comment style: `concise` or `detailed` | `concise` |
| `pr_comment_max_findings` | Maximum findings to include in PR comment summaries | `5` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Numeric score (0-100) |
| `grade` | Letter grade (A-F) |
| `grade_label` | Human-readable grade label |
| `policy_pass` | `true` when the selected policy profile passed |
| `verify_pass` | `true` when runtime verification passed |
| `max_severity` | Highest finding severity, or `none` |
| `findings_total` | Total number of findings across all severities |
| `report_path` | Path to the rendered report file, if `output` was set |
| `registry_payload_path` | Path to the machine-readable plugin ecosystem payload file, if requested |
| `submission_eligible` | `true` when the plugin met the submission threshold and passed the configured severity gate |
| `submission_performed` | `true` when a submission issue was created or an existing one was reused |
| `submission_issue_urls` | Comma-separated submission issue URLs |
| `submission_issue_numbers` | Comma-separated submission issue numbers |
| `action_exit_code` | Action execution exit code |
| `pr_comment_status` | PR comment status (`created`, `updated`, `unchanged`, `skipped`, `disabled`) |
| `pr_comment_id` | PR comment ID when available |
| `pr_comment_url` | PR comment URL when available |

The action also writes a concise summary to `GITHUB_STEP_SUMMARY` by default. The full report is written to the job log for `text` output, or to the file you pass through `output` for `json`, `markdown`, or `sarif`.

Mode notes:

- `scan` and `lint` respect `profile`, `config`, and `baseline`.
- `verify` respects `online` and writes a human-readable report for `format: text`.
- `submit` writes the plugin-quality artifact to `output` when provided, otherwise `plugin-quality.json`. `registry_payload_output` remains dedicated to the separate HOL registry payload.
- `online`, `submission_enabled`, and `upload_sarif` are the only common paths that intentionally reach beyond the runner after the scanner package itself has been installed.
- `pr_comment_status` currently defaults to `skipped` in this Marketplace wrapper path.

## Examples

### Basic scan with minimum score gate

```yaml
- uses: hashgraph-online/ai-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    min_score: 70
```

### SARIF output for GitHub Code Scanning

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashgraph-online/ai-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          mode: scan
          format: sarif
          fail_on_severity: high
          upload_sarif: true
```

This `plugin_dir: "."` pattern is correct for both single-plugin repositories and multi-plugin marketplace repositories. When `.agents/plugins/marketplace.json` exists, the action switches into repository mode and scans each local plugin entry declared under `./plugins/...`.

### With Cisco skill scanning

```yaml
- uses: hashgraph-online/ai-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    cisco_skill_scan: on
    cisco_policy: strict
    install_cisco: true
```

### Dogfood the source-repo action bundle

Use this only inside `hashgraph-online/ai-plugin-scanner`, where the action can install the adjacent source tree directly.

```yaml
- uses: ./action
  with:
    plugin_dir: "."
    install_source: local
```

### Export registry payload for ecosystem automation

```yaml
- uses: hashgraph-online/ai-plugin-scanner-action@v1
  id: scan
  with:
    plugin_dir: "."
    format: sarif
    upload_sarif: true
    registry_payload_output: ai-plugin-registry-payload.json

- name: Show trust signals
  run: |
    echo "Score: ${{ steps.scan.outputs.score }}"
    echo "Grade: ${{ steps.scan.outputs.grade_label }}"
    echo "Max severity: ${{ steps.scan.outputs.max_severity }}"
```

The registry payload mirrors the submission metadata used by HOL ecosystem automation, so the same scan can feed trust scoring, registry ingestion, badges, or awesome-list processing without reparsing the terminal output.

## Release Management

- This is the primary published repository for the action.
- `.github/workflows/sync-legacy-repo.yml` mirrors the same action bundle, exact release tags, and floating `v1` tag into `hashgraph-online/hol-codex-plugin-scanner-action`.
- Configure `LEGACY_ACTION_REPO_TOKEN` in this repository so the sync workflow can push into the legacy compatibility repository, publish autogenerated release notes there, and keep the old Marketplace slug current.
- Keep `scanner-version.txt` and `scanner-sha256.txt` aligned so the Marketplace action installs an exact reviewed wheel artifact instead of a moving package resolution.

## License

[Apache-2.0](https://github.com/hashgraph-online/ai-plugin-scanner/blob/main/LICENSE)
