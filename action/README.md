# HOL Codex Plugin Scanner GitHub Action

[![Latest Release](https://img.shields.io/github/v/release/hashgraph-online/hol-codex-plugin-scanner-action?display_name=tag)](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action/releases/latest)
[![Marketplace Repository](https://img.shields.io/badge/github-marketplace_repo-0A84FF)](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action)
[![Source of Truth](https://img.shields.io/badge/source-codex--plugin--scanner-111827)](https://github.com/hashgraph-online/codex-plugin-scanner/tree/main/action)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/hashgraph-online/codex-plugin-scanner/blob/main/LICENSE)

| ![Hashgraph Online Logo](https://hol.org/brand/Logo_Whole_Dark.png) | Marketplace-ready GitHub Action for scanning [Codex plugins](https://developers.openai.com/codex/plugins) for security, publishability, runtime readiness, and registry trust signals. The action emits structured reports, SARIF, policy results, and submission metadata while staying aligned to the main scanner release train.<br><br>[Latest Release](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action/releases/latest)<br>[Marketplace Repository](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action)<br>[Scanner Source of Truth](https://github.com/hashgraph-online/codex-plugin-scanner/tree/main/action)<br>[Report an Issue](https://github.com/hashgraph-online/codex-plugin-scanner/issues) |
| :--- | :--- |

This repository is the Marketplace-facing wrapper for the scanner action. The main scanner repo remains the source of truth, while this published action bundle keeps the required root `action.yml` layout for GitHub Marketplace.

The default Marketplace install path uses an exact `codex-plugin-scanner` PyPI release, verifies its PyPI provenance against `hashgraph-online/codex-plugin-scanner`, and only then installs it. After installation, the default `scan`, `lint`, and offline `verify` paths operate on local repository content only. Live network probing and submission automation remain explicit opt-in features.

Advanced distribution paths are available when you need them:

- `install_source: local` is the explicit dogfood path for `uses: ./action` inside the source repo.
- `ghcr.io/hashgraph-online/codex-plugin-scanner` is the container distribution for enterprise runners that prefer a reviewed OCI image over runtime package installation.

## Usage

```yaml
- name: Scan Codex Plugin
  uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
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
| `config` | Optional path to `.codex-plugin-scanner.toml` | `""` |
| `baseline` | Optional path to a baseline suppression file | `""` |
| `online` | Enable live network probing for `verify` mode | `false` |
| `upload_sarif` | Upload the generated SARIF report to GitHub code scanning when `mode: scan` | `false` |
| `sarif_category` | SARIF category used during GitHub code scanning upload | `codex-plugin-scanner` |
| `write_step_summary` | Write a concise markdown summary to the GitHub Actions job summary | `true` |
| `registry_payload_output` | Write a machine-readable Codex ecosystem payload JSON file for registry or awesome-list automation | `""` |
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
| `registry_payload_path` | Path to the machine-readable Codex ecosystem payload file, if requested |
| `submission_eligible` | `true` when the plugin met the submission threshold and passed the configured severity gate |
| `submission_performed` | `true` when a submission issue was created or an existing one was reused |
| `submission_issue_urls` | Comma-separated submission issue URLs |
| `submission_issue_numbers` | Comma-separated submission issue numbers |

The action also writes a concise summary to `GITHUB_STEP_SUMMARY` by default. The full report is written to the job log for `text` output, or to the file you pass through `output` for `json`, `markdown`, or `sarif`.

Mode notes:

- `scan` and `lint` respect `profile`, `config`, and `baseline`.
- `verify` respects `online` and writes a human-readable report for `format: text`.
- `submit` writes the plugin-quality artifact to `output` when provided, otherwise `plugin-quality.json`. `registry_payload_output` remains dedicated to the separate HOL registry payload.
- `online`, `submission_enabled`, and `upload_sarif` are the only common paths that intentionally reach beyond the runner after the scanner package itself has been installed.

## Examples

### Basic scan with minimum score gate

```yaml
- uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
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
      - uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
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
- uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    cisco_skill_scan: on
    cisco_policy: strict
    install_cisco: true
```

### Dogfood the source-repo action bundle

Use this only inside `hashgraph-online/codex-plugin-scanner`, where the action can install the adjacent source tree directly.

```yaml
- uses: ./action
  with:
    plugin_dir: "."
    install_source: local
```

### Export registry payload for Codex ecosystem automation

```yaml
- uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  id: scan
  with:
    plugin_dir: "."
    format: sarif
    upload_sarif: true
    registry_payload_output: codex-plugin-registry-payload.json

- name: Show trust signals
  run: |
    echo "Score: ${{ steps.scan.outputs.score }}"
    echo "Grade: ${{ steps.scan.outputs.grade_label }}"
    echo "Max severity: ${{ steps.scan.outputs.max_severity }}"
```

The registry payload mirrors the submission metadata used by HOL ecosystem automation, so the same scan can feed trust scoring, registry ingestion, badges, or awesome-list processing without reparsing the terminal output.

### Score 80+ and auto-file an awesome-list submission issue

When the scan reaches `80+` and does not trip the configured severity gate, the action opens or reuses a submission issue in `hashgraph-online/awesome-codex-plugins`. The issue body includes a machine-readable registry payload so downstream registry automation can ingest the same submission event.

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan plugin and submit if eligible
        id: scan
        uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
        with:
          plugin_dir: "."
          min_score: 80
          fail_on_severity: high
          submission_enabled: true
          submission_score_threshold: 80
          submission_token: ${{ secrets.AWESOME_CODEX_PLUGINS_TOKEN }}

      - name: Show submission issue
        if: steps.scan.outputs.submission_performed == 'true'
        run: echo "${{ steps.scan.outputs.submission_issue_urls }}"
```

Use a fine-grained token with `issues:write` on `hashgraph-online/awesome-codex-plugins`. `submission_token` is required when `submission_enabled: true`. The action deduplicates by an exact hidden plugin URL marker in the issue body, so repeated pushes reuse the open submission issue instead of opening duplicates.

### Markdown report as PR comment

```yaml
- uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  id: scan
  with:
    plugin_dir: "."
    format: markdown
    output: scan-report.md

- name: Comment PR
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const report = fs.readFileSync('scan-report.md', 'utf8');
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: report
      });
```

## Release Management

- Publish immutable releases for this Marketplace wrapper repository automatically from the source scanner repo when `action/` changes merge to `main`.
- Move the floating major tag `v1` to the latest compatible release.
- Keep this action in its own public repository for GitHub Marketplace publication.
- Configure `ACTION_REPO_TOKEN` as a secret in the source repository so `publish-action-repo.yml` can automatically sync this root-ready bundle, create the action-repo release, and publish autogenerated release notes.
- Optionally set `ACTION_REPOSITORY` in the source repository if the target repository should not be `hashgraph-online/hol-codex-plugin-scanner-action`.
- Sync the install metadata files (`scanner-version.txt`, `cisco-version.txt`, and `pypi-attestations-version.txt`) with the action bundle so the Marketplace wrapper always installs the same reviewed scanner release.

## Source of Truth

The source bundle for this action lives in the main scanner repository under `action/`. Release artifacts from that repository should export a root-ready action bundle for the dedicated Marketplace repository.

Direct edits in this Marketplace repository should stay limited to Marketplace-specific copy or metadata. Functional changes and release publication logic belong in `hashgraph-online/codex-plugin-scanner` so merges there can publish a matching action release automatically.

## License

[Apache-2.0](https://github.com/hashgraph-online/codex-plugin-scanner/blob/main/LICENSE)

## Mode-based workflow

Set `mode` to one of `scan`, `lint`, `verify`, or `submit`.

```yaml
- uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  with:
    mode: verify
    plugin_dir: "."
```

For `submit` mode, point `plugin_dir` at one concrete plugin directory. Repository-mode discovery is supported for `scan`, `lint`, and `verify`, but `submit` intentionally remains single-plugin.

For `scan` mode, set `upload_sarif: true` to emit and upload SARIF automatically instead of wiring a separate upload step by hand.

## Container Distribution

The scanner is also published as an OCI image for container-first environments:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  ghcr.io/hashgraph-online/codex-plugin-scanner:<version> \
  scan /workspace --format text
```

The image installs the scanner from the reviewed source tree at release build time. It is separate from the Marketplace action so teams that prefer `docker://` or explicit `docker run` flows can use a pinned image without changing the secure default action path.
