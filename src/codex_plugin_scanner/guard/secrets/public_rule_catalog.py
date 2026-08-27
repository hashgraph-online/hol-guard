"""Pre-rendered public output for the built-in detector catalog.

The CLI writes only these literal strings. Executable detector patterns,
candidate bytes, and scan results have no data-flow path to this output.
"""

from __future__ import annotations

PUBLIC_RULES_JSON = """{
  "detector_version": "guard-secrets-v1:1d8dc93ef4fc2a04",
  "rules": [
    {
      "description": "GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
      "family": "GitHub token",
      "rule_id": "github-token",
      "severity": "critical",
      "strong_format": true,
      "validation": "github"
    },
    {
      "description": "GitLab personal/project/group access token.",
      "family": "GitLab token",
      "rule_id": "gitlab-token",
      "severity": "critical",
      "strong_format": true,
      "validation": "gitlab"
    },
    {
      "description": "AWS long-lived or STS access key identifier.",
      "family": "AWS access key ID",
      "rule_id": "aws-access-key",
      "severity": "high",
      "strong_format": true,
      "validation": "aws"
    },
    {
      "description": "Slack bot, app, user, refresh, or service token.",
      "family": "Slack token",
      "rule_id": "slack-token",
      "severity": "critical",
      "strong_format": true,
      "validation": "slack"
    },
    {
      "description": "Slack incoming webhook URL.",
      "family": "Slack incoming webhook",
      "rule_id": "slack-webhook",
      "severity": "critical",
      "strong_format": true,
      "validation": "slack"
    },
    {
      "description": "Stripe secret or restricted API key.",
      "family": "Stripe secret key",
      "rule_id": "stripe-secret-key",
      "severity": "critical",
      "strong_format": true,
      "validation": "stripe"
    },
    {
      "description": "OpenAI project/service/account API key.",
      "family": "OpenAI API key",
      "rule_id": "openai-api-key",
      "severity": "critical",
      "strong_format": true,
      "validation": "openai"
    },
    {
      "description": "Anthropic API key.",
      "family": "Anthropic API key",
      "rule_id": "anthropic-api-key",
      "severity": "critical",
      "strong_format": true,
      "validation": "anthropic"
    },
    {
      "description": "Hugging Face user or organization token.",
      "family": "Hugging Face token",
      "rule_id": "huggingface-token",
      "severity": "high",
      "strong_format": true,
      "validation": "huggingface"
    },
    {
      "description": "npm granular or automation access token.",
      "family": "npm access token",
      "rule_id": "npm-token",
      "severity": "critical",
      "strong_format": true,
      "validation": "npm"
    },
    {
      "description": "PyPI scoped API token.",
      "family": "PyPI API token",
      "rule_id": "pypi-token",
      "severity": "critical",
      "strong_format": true,
      "validation": "pypi"
    },
    {
      "description": "Google Cloud/Firebase API key.",
      "family": "Google API key",
      "rule_id": "google-api-key",
      "severity": "high",
      "strong_format": true,
      "validation": "google"
    },
    {
      "description": "SendGrid API key.",
      "family": "SendGrid API key",
      "rule_id": "sendgrid-api-key",
      "severity": "critical",
      "strong_format": true,
      "validation": "sendgrid"
    },
    {
      "description": "Private-key material in PEM/OpenSSH-style form.",
      "family": "PEM private key",
      "rule_id": "pem-private-key",
      "severity": "critical",
      "strong_format": true,
      "validation": "none"
    },
    {
      "description": "Password embedded in a database connection URL.",
      "family": "Database URL password",
      "rule_id": "database-url-password",
      "severity": "critical",
      "strong_format": false,
      "validation": "none"
    },
    {
      "description": "Credential embedded in an HTTP(S) URL.",
      "family": "Basic-auth URL password",
      "rule_id": "basic-auth-url-password",
      "severity": "high",
      "strong_format": false,
      "validation": "none"
    },
    {
      "description": "JWT-like bearer token in credential context.",
      "family": "JWT bearer token",
      "rule_id": "jwt-token",
      "severity": "high",
      "strong_format": false,
      "validation": "none"
    },
    {
      "description": "High-entropy credential assignment accepted only with contextual evidence.",
      "family": "Contextual credential assignment",
      "rule_id": "credential-assignment",
      "severity": "high",
      "strong_format": false,
      "validation": "none"
    }
  ],
  "schema": "guard-secret-rules.v1"
}
"""

PUBLIC_RULES_TEXT = """HOL Guard Secrets detector guard-secrets-v1:1d8dc93ef4fc2a04
- GitHub token (critical, validates via github)
- GitLab token (critical, validates via gitlab)
- AWS access key ID (high, validates via aws)
- Slack token (critical, validates via slack)
- Slack incoming webhook (critical, validates via slack)
- Stripe secret key (critical, validates via stripe)
- OpenAI API key (critical, validates via openai)
- Anthropic API key (critical, validates via anthropic)
- Hugging Face token (high, validates via huggingface)
- npm access token (critical, validates via npm)
- PyPI API token (critical, validates via pypi)
- Google API key (high, validates via google)
- SendGrid API key (critical, validates via sendgrid)
- PEM private key (critical)
- Database URL password (critical)
- Basic-auth URL password (high)
- JWT bearer token (high)
- Contextual credential assignment (high)

"""

__all__ = ["PUBLIC_RULES_JSON", "PUBLIC_RULES_TEXT"]
