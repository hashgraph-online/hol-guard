from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets import scan_repository_secrets, scan_secret_text, secret_rule_catalog
from codex_plugin_scanner.guard.secrets import secret_repository_scanner as secret_repository_scanner_module
from codex_plugin_scanner.guard.secrets.cli import main as secrets_cli_main


def _github_token() -> str:
    return "ghp_" + ("A" * 40)


def _generic_secret() -> str:
    return "Q7v9K2mX4pR8sT6wY3nB5cD1fG0hJ9kL"


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_provider_secret_is_detected_without_public_candidate() -> None:
    secret = _github_token()
    result = scan_secret_text(f"GITHUB_TOKEN={secret}\n", path="src/config.py")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "github-token"
    assert finding.severity == "critical"
    assert finding.confidence == "high"
    payload = result.to_public_dict()
    encoded = json.dumps(payload)
    assert secret not in encoded
    assert "candidate" not in encoded


def test_provider_secret_remains_detectable_in_documentation() -> None:
    secret = _github_token()
    result = scan_secret_text(f"token = {secret}\n", path="docs/example.md")

    assert [finding.rule_id for finding in result.findings] == ["github-token"]


def test_contextual_high_entropy_assignment_is_detected() -> None:
    secret = _generic_secret()
    result = scan_secret_text(f"PAYMENTS_API_SECRET={secret}\n", path="app/settings.py")

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "credential-assignment"
    assert result.findings[0].confidence in {"medium", "high"}


def test_generic_random_value_without_credential_context_is_not_detected() -> None:
    secret = _generic_secret()
    result = scan_secret_text(f"BUILD_CACHE_KEY={secret}\n", path="app/settings.py")

    assert result.findings == ()


def test_obvious_documentation_placeholder_is_suppressed() -> None:
    result = scan_secret_text(
        "API_SECRET=replace_me_with_your_secret\n",
        path="docs/configuration.md",
    )

    assert result.findings == ()


def test_database_url_password_is_contextually_detected() -> None:
    password = _generic_secret()
    result = scan_secret_text(
        f"DATABASE_URL=postgres://service:{password}@db.internal/app\n",
        path=".env.production",
    )

    assert any(finding.rule_id == "database-url-password" for finding in result.findings)
    assert password not in json.dumps(result.to_public_dict())


def test_fingerprint_is_scoped_to_caller_key() -> None:
    secret = _github_token()
    finding = scan_secret_text(f"TOKEN={secret}\n").findings[0]

    first = finding.fingerprint(b"tenant-a")
    second = finding.fingerprint(b"tenant-b")
    assert first != second
    assert secret not in first
    assert secret not in second
    with pytest.raises(ValueError):
        finding.fingerprint(b"")


def test_rule_catalog_contains_validatable_provider_families() -> None:
    rules = secret_rule_catalog()
    validation_kinds = {str(rule["validation"]) for rule in rules}

    assert {"github", "gitlab", "aws", "slack", "stripe", "openai", "anthropic", "npm", "pypi"} <= validation_kinds


def test_truncated_scan_keeps_documented_finding_order() -> None:
    aws_key = "AKIA" + ("B" * 16)
    github_token = _github_token()
    result = scan_secret_text(
        f"AWS_ACCESS_KEY_ID={aws_key}\nGITHUB_TOKEN={github_token}\n",
        path="config.env",
        max_findings=2,
    )

    assert [(finding.line, finding.rule_id) for finding in result.findings] == [
        (1, "aws-access-key"),
        (2, "github-token"),
    ]


def test_repository_scan_skips_binary_and_does_not_emit_absolute_path(tmp_path: Path) -> None:
    secret = _github_token()
    (tmp_path / "config.py").write_text(f"TOKEN={secret}\n")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00" + secret.encode())

    result = scan_repository_secrets(tmp_path)
    payload = result.to_public_dict()
    encoded = json.dumps(payload)

    assert result.findings
    assert all(not finding.path.startswith(str(tmp_path)) for finding in result.findings)
    assert secret not in encoded
    assert "image.png" not in encoded


def test_history_scan_finds_secret_removed_from_head(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "guard@example.invalid")
    _git(tmp_path, "config", "user.name", "Guard Test")
    secret = _github_token()
    target = tmp_path / "config.py"
    target.write_text(f"TOKEN={secret}\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "add config")
    target.write_text("TOKEN_FROM_ENV = True\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "remove credential")

    head_only = scan_repository_secrets(tmp_path, include_history=False)
    history = scan_repository_secrets(tmp_path, include_history=True, max_commits=2)
    bounded_history = scan_repository_secrets(tmp_path, include_history=True, max_commits=1)

    assert head_only.findings == ()
    assert any(finding.source == "git_history" for finding in history.findings)
    assert history.truncated is False and history.truncation_reasons == ()
    assert bounded_history.truncated is True and bounded_history.truncation_reasons == ("max_commits",)
    assert secret not in json.dumps(history.to_public_dict())


def test_history_enumeration_failure_is_not_reported_as_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _git(tmp_path, "init")
    monkeypatch.setattr(secret_repository_scanner_module, "_git_commits", lambda _root, _limit: None)

    result = scan_repository_secrets(tmp_path, include_history=True)

    assert result.truncated is True and result.truncation_reasons == ()
    assert "git_history_enumeration_failed" in result.errors


def test_history_changed_path_failure_is_not_reported_as_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _git(tmp_path, "init")
    monkeypatch.setattr(secret_repository_scanner_module, "_git_commits", lambda _root, _limit: ["a" * 40])
    monkeypatch.setattr(secret_repository_scanner_module, "_git_changed_paths", lambda _root, _commit: None)

    result = scan_repository_secrets(tmp_path, include_history=True)

    assert result.truncated is True and result.truncation_reasons == ()
    assert "git_history_changed_paths_failed" in result.errors


def test_repository_scan_respects_finding_limit(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"secret-{index}.txt").write_text(f"TOKEN={_github_token()}{index}\n")

    result = scan_repository_secrets(tmp_path, max_findings=2)

    assert len(result.findings) <= 2
    assert result.truncated is True and result.truncation_reasons == ("max_findings",)


def test_cli_scan_json_returns_public_payload(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = secrets_cli_main(["scan", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["schema"] == "guard-repository-secret-scan.v1"
    assert captured.err == ""


def test_cli_rules_lists_detector_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = secrets_cli_main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "HOL Guard Secrets detector" in captured.out
    assert "GitHub token" in captured.out


def test_cli_fail_on_findings_returns_three_without_printing_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = _github_token()
    target = tmp_path / "config.env"
    target.write_text(f"GITHUB_TOKEN={secret}\n")

    exit_code = secrets_cli_main(["scan", str(target), "--fail-on-findings"])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "GitHub token" in captured.out
    assert secret not in captured.out
    assert secret not in captured.err


def test_cli_missing_target_returns_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = secrets_cli_main(["scan", str(tmp_path / "missing")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error: secret scan target does not exist" in captured.err
