from __future__ import annotations

import contextlib
import io
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.secrets.cli import main as standalone_secrets_main
from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook, uninstall_precommit_hook
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _init_repo(root: Path) -> None:
    _git(root, "init")
    _git(root, "config", "user.email", "guard@example.invalid")
    _git(root, "config", "user.name", "Guard Test")


def _github_token() -> str:
    return "ghp_" + ("A" * 40)


def _run_native(argv: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv = guard_cli.sys.argv
    try:
        guard_cli.sys.argv = ["hol-guard"]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv = original_argv
    return exit_code, output.getvalue(), error.getvalue()


def test_staged_scan_reads_index_not_unstaged_worktree(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    target = tmp_path / "config.env"
    target.write_text("SAFE_VALUE=hello\n", encoding="utf-8")
    _git(tmp_path, "add", "config.env")
    secret = _github_token()
    target.write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")

    staged = scan_staged_secrets(tmp_path)
    assert staged.findings == ()

    _git(tmp_path, "add", "config.env")
    staged_secret = scan_staged_secrets(tmp_path)
    assert [finding.rule_id for finding in staged_secret.findings] == ["github-token"]
    assert staged_secret.findings[0].source == "staged"
    assert secret not in json.dumps(staged_secret.to_public_dict())


def test_staged_scan_resolves_repository_root_from_nested_directory(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    nested = tmp_path / "packages" / "app"
    nested.mkdir(parents=True)
    (tmp_path / "config.env").write_text(f"GITHUB_TOKEN={_github_token()}\n", encoding="utf-8")
    _git(tmp_path, "add", "config.env")

    result = scan_staged_secrets(nested)

    assert result.truncated is False
    assert [finding.path for finding in result.findings] == ["config.env"]


def test_staged_scan_non_git_target_is_explicitly_partial(tmp_path: Path) -> None:
    result = scan_staged_secrets(tmp_path)

    assert result.truncated is True
    assert result.findings == ()
    assert result.errors == ("git_staged_enumeration_failed",)


def test_native_partial_staged_scan_returns_infrastructure_error(tmp_path: Path) -> None:
    exit_code, output, error = _run_native(["secrets", "scan", str(tmp_path), "--staged"])

    assert exit_code == 2
    assert "Scan coverage is partial" in output
    assert "finding(s)" in output
    assert "git_staged_enumeration_failed" in error


def test_standalone_partial_history_scan_returns_infrastructure_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = standalone_secrets_main(["scan", str(tmp_path), "--history"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "history_requested_for_non_git_target" in captured.err


def test_native_rules_bypass_guard_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_guard_parser(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Guard parser must not initialize for local Secrets commands")

    monkeypatch.setattr(guard_cli, "_build_parser", fail_guard_parser)
    exit_code, output, error = _run_native(["secrets", "rules", "--json"])

    assert exit_code == 0
    assert error == ""
    payload = json.loads(output)
    assert payload["schema"] == "guard-secret-rules.v1"
    assert any(rule["rule_id"] == "github-token" for rule in payload["rules"])
    public_fields = {"description", "family", "rule_id", "severity", "strong_format", "validation"}
    assert all(set(rule) == public_fields for rule in payload["rules"])
    assert all("pattern" not in rule and "candidate" not in rule for rule in payload["rules"])


def test_public_rules_catalog_matches_detector_metadata() -> None:
    from codex_plugin_scanner.guard.secrets.public_rule_catalog import PUBLIC_RULES_JSON
    from codex_plugin_scanner.guard.secrets.secret_detection import detector_version, secret_rule_catalog

    payload = json.loads(PUBLIC_RULES_JSON)
    assert payload["detector_version"] == detector_version()
    assert payload["rules"] == secret_rule_catalog()


def test_native_staged_scan_fails_on_findings_without_printing_secret(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    secret = _github_token()
    (tmp_path / "config.env").write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")
    _git(tmp_path, "add", "config.env")

    exit_code, output, error = _run_native(["secrets", "scan", str(tmp_path), "--staged", "--fail-on-findings"])

    assert exit_code == 3
    assert error == ""
    assert "GitHub token" in output
    assert "config.env:1" in output
    assert secret not in output


def test_native_staged_json_reports_staged_source(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "config.env").write_text(f"TOKEN={_github_token()}\n", encoding="utf-8")
    _git(tmp_path, "add", "config.env")

    exit_code, output, error = _run_native(["secrets", "scan", str(tmp_path), "--staged", "--json"])

    assert exit_code == 0
    assert error == ""
    payload = json.loads(output)
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["source"] == "staged"
    assert "candidate" not in output


def test_precommit_install_is_idempotent(tmp_path: Path) -> None:
    _init_repo(tmp_path)

    first = install_precommit_hook(tmp_path)
    second = install_precommit_hook(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-commit"

    assert first.status == "installed"
    assert second.status == "already_installed"
    assert first.chained_existing is False
    content = hook.read_text(encoding="utf-8")
    assert "HOL_GUARD_SECRETS_PRE_COMMIT_V1" in content
    assert "hol-guard secrets scan --staged --fail-on-findings" in content
    assert hook.stat().st_mode & 0o100


def test_precommit_install_chains_and_uninstall_restores_existing_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    original = b"#!/bin/sh\necho existing-hook\n"
    hook.write_bytes(original)
    hook.chmod(0o755)

    installed = install_precommit_hook(tmp_path)
    backup = hook.with_name("pre-commit.hol-guard-user")
    assert installed.chained_existing is True
    assert backup.read_bytes() == original
    assert "HOL_GUARD_SECRETS_PRE_COMMIT_V1" in hook.read_text(encoding="utf-8")

    exit_code, output, error = _run_native(["secrets", "uninstall-hook", str(tmp_path)])
    assert exit_code == 0
    assert error == ""
    assert "pre-commit hook uninstalled: restored" in output
    assert hook.read_bytes() == original
    assert hook.stat().st_mode & 0o100
    assert not backup.exists()


def test_precommit_install_refuses_custom_hooks_path(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _git(tmp_path, "config", "core.hooksPath", ".custom-hooks")

    with pytest.raises(ValueError, match=r"custom core.hooksPath"):
        install_precommit_hook(tmp_path)


def test_precommit_install_rejects_symlinked_hooks_directory(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hooks = tmp_path / ".git" / "hooks"
    preserved_hooks = tmp_path / ".git" / "hooks-original"
    hooks.rename(preserved_hooks)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        hooks.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(ValueError, match="real trusted directory"):
        install_precommit_hook(tmp_path)
    with pytest.raises(ValueError, match="real trusted directory"):
        uninstall_precommit_hook(tmp_path)

    assert list(outside.iterdir()) == []


def test_precommit_uninstall_does_not_remove_foreign_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    original = b"#!/bin/sh\necho foreign\n"
    hook.write_bytes(original)
    hook.chmod(0o755)

    result = uninstall_precommit_hook(tmp_path)

    assert result.status == "not_installed"
    assert hook.read_bytes() == original


def test_precommit_uninstall_accepts_missing_hooks_directory(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hooks = tmp_path / ".git" / "hooks"
    hooks.rename(tmp_path / ".git" / "hooks-preserved")

    result = uninstall_precommit_hook(tmp_path)

    assert result.status == "not_installed"
    assert result.chained_existing is False
