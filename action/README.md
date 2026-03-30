# HOL Codex Plugin Scanner GitHub Action

Scan your [Codex plugin](https://developers.openai.com/codex/plugins) for security, publishability, and best practices. The action emits a `0-100` score, a grade, and the requested report format.

This README is intentionally root-ready for a dedicated GitHub Marketplace action repository. GitHub Marketplace requires that repository to contain a single root `action.yml` and no workflow files.

## Usage

```yaml
- name: Scan Codex Plugin
  uses: your-org/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "./my-plugin"
    min_score: 70
    fail_on_severity: high
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `plugin_dir` | Path to the plugin directory to scan | `.` |
| `format` | Output format: `text`, `json`, `markdown`, `sarif` | `text` |
| `output` | Write report to this file path | `""` |
| `min_score` | Fail if score is below this threshold (0-100) | `0` |
| `fail_on_severity` | Fail on findings at or above this severity: `none`, `critical`, `high`, `medium`, `low`, `info` | `none` |
| `cisco_skill_scan` | Cisco skill-scanner mode: `auto`, `on`, `off` | `auto` |
| `cisco_policy` | Cisco policy preset: `permissive`, `balanced`, `strict` | `balanced` |
| `install_cisco` | Install the Cisco skill-scanner dependency for live skill scanning | `false` |
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
| `submission_eligible` | `true` when the plugin met the submission threshold and passed the configured severity gate |
| `submission_performed` | `true` when a submission issue was created or an existing one was reused |
| `submission_issue_urls` | Comma-separated submission issue URLs |
| `submission_issue_numbers` | Comma-separated submission issue numbers |

The report itself is written to the job log for `text` output, or to the file you pass through `output` for `json`, `markdown`, or `sarif`.

## Examples

### Basic scan with minimum score gate

```yaml
- uses: your-org/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    min_score: 70
```

### SARIF output for GitHub Code Scanning

```yaml
- uses: your-org/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    format: sarif
    output: codex-plugin-scanner.sarif
    fail_on_severity: high
```

### With Cisco skill scanning

```yaml
- uses: your-org/hol-codex-plugin-scanner-action@v1
  with:
    plugin_dir: "."
    cisco_skill_scan: on
    cisco_policy: strict
    install_cisco: true
```

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
        uses: your-org/hol-codex-plugin-scanner-action@v1
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
- uses: your-org/hol-codex-plugin-scanner-action@v1
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

- Publish immutable releases such as `v1.2.0`.
- Move the floating major tag `v1` to the latest compatible release.
- Keep this action in its own public repository for GitHub Marketplace publication.
- Configure `ACTION_REPO_TOKEN` in the source repository so `publish-action-repo.yml` can sync this root-ready bundle automatically.
- Optionally set `ACTION_REPOSITORY` in the source repository if the target repository should not be `hashgraph-online/hol-codex-plugin-scanner-action`.

## Source Of Truth

The source bundle for this action lives in the main scanner repository under `action/`. Release artifacts from that repository should export a root-ready action bundle for the dedicated Marketplace repository.

## License

[Apache-2.0](https://github.com/hashgraph-online/codex-plugin-scanner/blob/main/LICENSE)
