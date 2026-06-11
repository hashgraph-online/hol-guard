# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in `ai-plugin-scanner`, please report it privately:

1. Do not open a public issue for the vulnerability.
2. Email `security@hol.org`.
3. Include the affected package or surface (`hol-guard`, `plugin-scanner`, GitHub Action, container image, or release workflow).
4. Include reproduction steps, impact, and any known mitigations.

We aim to:

- acknowledge vulnerability reports within 48 hours
- provide an initial triage response within 14 days
- resolve confirmed issues as quickly as practical based on severity and release risk

## Scope

This policy covers:

- the Python packages published from this repository
- the reviewed container image
- the GitHub Action bundle sourced from this repository
- release and automation workflows maintained in this repository

## Secure Use Guidance

For users of the project:

- keep the scanner and Guard packages updated to the latest supported release line
- review plugin code and MCP configuration before enabling it in a local harness
- avoid committing secrets, API keys, or local environment files into plugin repositories
- prefer HTTPS-only remote endpoints and pinned GitHub Actions in plugin repositories

The scanner and Guard help identify risky patterns, but they are not a substitute for manual review or a full secure development lifecycle.
