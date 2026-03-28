# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. Do not open a public issue.
2. Email us at security@hol.org with details.
3. Include steps to reproduce, expected vs actual behavior, and potential impact.
4. We will acknowledge within 48 hours and aim to resolve within 7 days.

## Security Best Practices

This tool helps you follow security best practices for Codex plugins. For the latest guidance, see the [Codex Security documentation](https://developers.openai.com/codex/security).

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
