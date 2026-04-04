# HOL Codex Plugin Scanner GitHub Action

Scan your [Codex plugin](https://developers.openai.com/codex/plugins) for security, publishability, and best practices. The action emits a `0-100` score, a grade, and the requested report format.

This README is intentionally root-ready for a dedicated GitHub Marketplace action repository. GitHub Marketplace requires that repository to contain a single root `action.yml` and no workflow files.

## Usage

```yaml
- name: Scan Codex Plugin
  uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "./my-plugin"
    min_score: 70
    fail_on_severity: high
```

If your repository exposes multiple plugins from `.agents/plugins/marketplace.json`, keep `plugin_dir: "."`. The action will discover local `./plugins/...` entries automatically, scan each local plugin, and skip remote marketplace entries.

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
| `install_cisco` | Install the scanner with its `cisco` extra enabled | `false` |
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
      - uses: actions/checkout@v6
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
The action installs the scanner with its published `cisco` extra enabled, so the optional Cisco analysis path stays aligned with the dependency declared in `pyproject.toml`.

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
      - uses: actions/checkout@v6

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
  uses: actions/github-script@v8
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

- Publish immutable releases such as `v1.4.0`.
- Move the floating major tag `v1` to the latest compatible release.
- Keep this action in its own public repository for GitHub Marketplace publication.
- Configure `ACTION_REPO_TOKEN` in the source repository so `publish-action-repo.yml` can sync this root-ready bundle automatically.
- Optionally set `ACTION_REPOSITORY` in the source repository if the target repository should not be `hashgraph-online/hol-codex-plugin-scanner-action`.

## Source Of Truth

The source bundle for this action lives in the main scanner repository under `action/`. Release artifacts from that repository should export a root-ready action bundle for the dedicated Marketplace repository.

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
