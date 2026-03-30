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

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Numeric score (0-100) |
| `grade` | Letter grade (A-F) |

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

## Source Of Truth

The source bundle for this action lives in the main scanner repository under `action/`. Release artifacts from that repository should export a root-ready action bundle for the dedicated Marketplace repository.

## License

[Apache-2.0](https://github.com/hashgraph-online/codex-plugin-scanner/blob/main/LICENSE)
