# AI Plugin Scanner Action Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. Do not open a public issue.
2. Email us at security@hol.org with details.
3. Include steps to reproduce, expected vs actual behavior, and potential impact.
4. If the issue is in the source scanner, include the corresponding `plugin-scanner` version (or legacy alias `codex-plugin-scanner`) and commit when possible.
5. We will acknowledge within 48 hours and aim to resolve within 7 days.

## Scope

This repository is the canonical GitHub Action bundle. Some issues belong here, some belong in the legacy compatibility repository, and some belong in the source repository:

- Canonical action-repository scope:
  - incorrect `action.yml` metadata
  - broken README examples for the canonical action slug
  - missing release tags or release notes in `hashgraph-online/ai-plugin-scanner-action`
- Legacy compatibility scope:
  - problems specific to `hashgraph-online/hol-codex-plugin-scanner-action`
  - mirror drift between the canonical and compatibility repositories
- Source-repository scope:
  - scanner findings, scoring, verification, or submission logic
  - CLI behavior
  - release automation that produces this bundle

Source repository:

- [hashgraph-online/ai-plugin-scanner](https://github.com/hashgraph-online/ai-plugin-scanner)

Legacy compatibility repository:

- [hashgraph-online/hol-codex-plugin-scanner-action](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action)

## Security Best Practices

This tool helps you follow security best practices for AI plugin repositories. For Codex-specific guidance, see the [Codex Security documentation](https://developers.openai.com/codex/security).

### For Plugin Authors

- Never commit API keys, tokens, or secrets to your repository.
- Use environment variables for sensitive configuration.
- Avoid dangerous shell commands in `.mcp.json` configurations.
- Include a `SECURITY.md` in your plugin repository.
- Use permissive licenses (Apache-2.0 or MIT) for clarity.

### For Scanner Users

- This scanner checks for common patterns but does not guarantee security.
- Always review plugin code manually before installation.
- Keep this tool updated for the latest check definitions.
