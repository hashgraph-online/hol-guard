"""L315: Tests for Guard daemon log redaction helpers.

Verifies that sensitive values are removed before Guard prints or syncs them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import redaction
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import product
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.redaction import redact_local_path, redact_sensitive_text, redact_text
from codex_plugin_scanner.guard.store import GuardStore


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

    @pytest.mark.parametrize(
        ("line", "secret_fragment"),
        [
            ("//registry.npmjs.org/:_authToken=npm_ultra_secret_token_123", "npm_ultra_secret_token_123"),
            ("index-url = https://__token__:pypi-very-secret@pypi.example/simple", "pypi-very-secret"),
            ("PIP_EXTRA_INDEX_URL=https://user:super-secret@repo.example/simple", "super-secret"),
        ],
    )
    def test_package_registry_token_redaction_fuzz(self, line: str, secret_fragment: str) -> None:
        result = redact_text(line)
        assert secret_fragment not in result.text
        assert result.count >= 1

    def test_clean_text_returns_zero_count(self) -> None:
        result = redact_text("Running build step: pnpm install")
        assert result.count == 0
        assert result.text == "Running build step: pnpm install"
        assert result.classifiers == ()

    def test_result_hashes_redacted_text_not_secret_bearing_input(self) -> None:
        import hashlib

        original = "MY_TOKEN=abcdef"
        result = redact_text(original)
        expected_sha = hashlib.sha256(result.text.encode("utf-8")).hexdigest()
        assert result.original_sha256 == expected_sha
        assert result.original_sha256 != hashlib.sha256(original.encode("utf-8")).hexdigest()

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


class TestLocalPathRedaction:
    def test_redact_local_path_replaces_home_prefix(self) -> None:
        assert redact_local_path("/Users/alice/.hol-guard/config.toml", home_dir=Path("/Users/alice")) == (
            "~/.hol-guard/config.toml"
        )

    def test_redact_local_path_survives_unresolved_current_home(self, monkeypatch) -> None:
        monkeypatch.setattr(redaction, "_current_home_path", lambda: None)

        assert redact_local_path("/Users/alice/.hol-guard/config.toml") == "~/.hol-guard/config.toml"

    def test_status_payload_omits_raw_username_and_home_paths(self, tmp_path: Path, monkeypatch) -> None:
        user_home = Path("/Users/alice")
        guard_home = user_home / ".hol-guard"
        workspace = user_home / "project"
        context = HarnessContext(home_dir=user_home, workspace_dir=workspace, guard_home=guard_home)
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(guard_home=guard_home, workspace=workspace)
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(str(user_home / ".codex" / "config.toml"),),
            artifacts=(),
        )
        monkeypatch.setattr(product, "detect_all", lambda _context: [detection])

        payload = product.build_guard_status_payload(context, store, config)
        text = json.dumps(payload)

        assert "alice" not in text
        assert "/Users/" not in text
        assert payload["guard_home"] == "~/.hol-guard"
        assert payload["workspace"] == "~/project"
        assert payload["harnesses"][0]["config_paths"] == ["~/.codex/config.toml"]

    def test_settings_json_output_omits_raw_username_and_home_paths(self, capsys) -> None:
        emit_guard_payload(
            "settings",
            {
                "generated_at": "2026-01-01T00:00:00Z",
                "guard_home": "/Users/alice/.hol-guard",
                "config_path": "/Users/alice/.hol-guard/config.toml",
                "settings": {"mode": "prompt", "security_level": "balanced"},
            },
            True,
        )
        output = capsys.readouterr().out

        assert "alice" not in output
        assert "/Users/" not in output
        assert '"guard_home": "~/.hol-guard"' in output
        assert '"config_path": "~/.hol-guard/config.toml"' in output


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
