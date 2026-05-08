"""L315: Tests for Guard daemon log redaction helpers.

Verifies that sensitive values are removed before Guard prints or syncs them.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.redaction import redact_sensitive_text, redact_text


class TestRedactText:
    """Core redaction patterns that must fire before logging or syncing."""

    def test_bearer_token_is_redacted(self) -> None:
        result = redact_text("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
        assert "eyJhbGciOiJSUzI1NiJ9" not in result.text
        assert result.count >= 1
        assert "bearer-token" in result.classifiers

    def test_openai_sk_token_is_redacted(self) -> None:
        result = redact_text("OPENAI_API_KEY=sk-abcdefgh12345678")
        assert "sk-abcdefgh12345678" not in result.text
        assert result.count >= 1
        assert "openai-token" in result.classifiers

    def test_github_token_is_redacted(self) -> None:
        result = redact_text("Cloning with token ghp_abcdef1234567890abcdef1234567890")
        assert "ghp_abcdef1234567890abcdef1234567890" not in result.text
        assert "github-token" in result.classifiers

    def test_aws_access_key_is_redacted(self) -> None:
        result = redact_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result.text
        assert "aws-access-key" in result.classifiers

    def test_npm_auth_token_is_redacted(self) -> None:
        result = redact_text("_authToken=npm_my_secret_token_12345678")
        assert "npm_my_secret_token_12345678" not in result.text
        assert "npm-token" in result.classifiers

    def test_private_key_block_is_redacted(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        result = redact_text(pem)
        assert "MIIEpAIBAAKCAQEA" not in result.text
        assert "private-key" in result.classifiers

    def test_secret_env_var_is_redacted(self) -> None:
        result = redact_text("MY_APP_SECRET=supersecretvalue123")
        assert "supersecretvalue123" not in result.text
        assert "secret-env" in result.classifiers

    def test_token_env_var_is_redacted(self) -> None:
        result = redact_text("AUTH_TOKEN=hunter2")
        assert "hunter2" not in result.text
        assert "secret-env" in result.classifiers

    def test_password_env_var_is_redacted(self) -> None:
        result = redact_text("DB_PASSWORD=correcthorsebatterystaple")
        assert "correcthorsebatterystaple" not in result.text
        assert "secret-env" in result.classifiers

    def test_database_connection_string_is_redacted(self) -> None:
        result = redact_text("postgresql://user:hunter2@db.example.com:5432/prod")
        assert "hunter2" not in result.text
        assert "connection-string" in result.classifiers

    def test_redis_url_is_redacted(self) -> None:
        result = redact_text("redis://default:secretpassword@cache.example.com:6379/0")
        assert "secretpassword" not in result.text
        assert "connection-string" in result.classifiers

    def test_connection_env_url_is_redacted(self) -> None:
        result = redact_text("DATABASE_URL=postgres://user:pw@host/db")
        assert "postgres://user:pw@host/db" not in result.text
        assert "connection-env" in result.classifiers

    def test_clean_text_returns_zero_count(self) -> None:
        result = redact_text("Running build step: pnpm install")
        assert result.count == 0
        assert result.text == "Running build step: pnpm install"
        assert result.classifiers == ()

    def test_result_preserves_sha256_of_original(self) -> None:
        import hashlib

        original = "MY_TOKEN=abcdef"
        result = redact_text(original)
        expected_sha = hashlib.sha256(original.encode("utf-8")).hexdigest()
        assert result.original_sha256 == expected_sha

    def test_result_is_frozen(self) -> None:
        result = redact_text("clean text")
        with pytest.raises((AttributeError, TypeError)):
            result.count = 99  # type: ignore[misc]

    def test_multiple_secrets_in_one_string(self) -> None:
        text = "sk-abcdefgh12345678 and ghp_abcdef1234567890abcdef1234567890"
        result = redact_text(text)
        assert "sk-abcdefgh12345678" not in result.text
        assert "ghp_abcdef1234567890abcdef1234567890" not in result.text
        assert result.count >= 2

    def test_to_dict_excludes_redacted_text(self) -> None:
        result = redact_text("MY_SECRET=hunter2")
        d = result.to_dict()
        assert "text" not in d
        assert "count" in d
        assert "classifiers" in d
        assert "original_sha256" in d

    def test_classifier_deduplication(self) -> None:
        """Two tokens of the same type produce one classifier entry, not two."""
        text = "sk-aaaaaaa11111111 sk-bbbbbbb22222222"
        result = redact_text(text)
        assert result.classifiers.count("openai-token") == 1

    def test_false_positive_curl_header_not_redacted(self) -> None:
        """Routine health-check Accept header must not be stripped."""
        result = redact_text("curl -H 'Accept: application/json' http://localhost:4000/health")
        assert "application/json" in result.text
        assert result.count == 0


class TestRedactSensitiveText:
    """Quick inline redaction for log lines that do not need full metadata."""

    def test_sk_token_is_redacted(self) -> None:
        result = redact_sensitive_text("key=sk-abcdef1234567890")
        assert "sk-abcdef1234567890" not in result

    def test_api_key_assignment_is_redacted(self) -> None:
        result = redact_sensitive_text("api_key: my_secret_value_here")
        assert "my_secret_value_here" not in result

    def test_clean_text_unchanged(self) -> None:
        text = "Daemon started on port 4001"
        assert redact_sensitive_text(text) == text


class TestRedactTextApprovalWakeScenarios:
    """L314/L315 combined: redaction must apply to approval-request log lines.

    These scenarios simulate what Guard logs when an approval URL is accessed
    without the browser dashboard open.  The auth token embedded in the URL
    fragment must never appear in plain text in any log output.
    """

    def test_approval_url_with_token_fragment_is_redacted(self) -> None:
        url_log = "Approval URL opened: http://localhost:4001/#guard-token=ghp_faketoken123456789012"
        result = redact_text(url_log)
        assert "ghp_faketoken123456789012" not in result.text

    def test_approval_url_without_token_is_not_altered(self) -> None:
        url_log = "Approval URL: http://localhost:4001/approvals/req-abc"
        result = redact_text(url_log)
        assert "http://localhost:4001/approvals/req-abc" in result.text
        assert result.count == 0
