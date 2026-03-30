# Codex Plugin Scanner GitHub Action

Scan your [Codex plugin](https://developers.openai.com/codex/plugins) for security issues and best practices. Outputs a 0-100 score with detailed findings.

## Usage

```yaml
- name: Scan Codex Plugin
  uses: hashgraph-online/codex-plugin-scanner/action@v1
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
| `install_cisco` | Install the cisco extra for skill scanning | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Numeric score (0-100) |
| `grade` | Letter grade (A-F) |
| `report` | Full report text |

## Examples

### Basic scan with minimum score gate

```yaml
- uses: hashgraph-online/codex-plugin-scanner/action@v1
  with:
    plugin_dir: "."
    min_score: 70
```

### SARIF output for GitHub Code Scanning

```yaml
- uses: hashgraph-online/codex-plugin-scanner/action@v1
  with:
    plugin_dir: "."
    format: sarif
    output: codex-plugin-scanner.sarif
    fail_on_severity: high
```

### With Cisco skill scanning

```yaml
- uses: hashgraph-online/codex-plugin-scanner/action@v1
  with:
    plugin_dir: "."
    cisco_skill_scan: on
    cisco_policy: strict
    install_cisco: true
```

### Markdown report as PR comment

```yaml
- uses: hashgraph-online/codex-plugin-scanner/action@v1
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

## License

[Apache-2.0](https://github.com/hashgraph-online/codex-plugin-scanner/blob/main/LICENSE)
