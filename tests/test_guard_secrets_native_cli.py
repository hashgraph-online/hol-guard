"""End-to-end coverage for ``hol-guard secrets`` through the native runtime.

Detector, scanner and hook parity is pinned by the Rust vectors in
``rust/crates/guard-runtime/testdata/secrets_cli``; these tests cover the
argument handling, rendering and exit codes of the Python shim.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.secrets.cli import main as standalone_secrets_main


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _init_repo(root: Path) -> None:
    _git(root, "init")
    _git(root, "config", "user.email", "guard@example.invalid")
    _git(root, "config", "user.name", "Guard Test")
    # A developer's global core.hooksPath must not leak into hook tests.
    _git(root, "config", "core.hooksPath", "")


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

    exit_code, output, error = _run_native(["secrets", "scan", str(tmp_path), "--staged", "--json"])
    assert (exit_code, error) == (0, "")
    assert json.loads(output)["findings"] == []

    _git(tmp_path, "add", "config.env")
    exit_code, output, error = _run_native(["secrets", "scan", str(tmp_path), "--staged", "--json"])
    assert (exit_code, error) == (0, "")
    payload = json.loads(output)
    assert [finding["rule_id"] for finding in payload["findings"]] == ["github-token"]
    assert payload["findings"][0]["source"] == "staged"
    assert secret not in output


def test_staged_scan_resolves_repository_root_from_nested_directory(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    nested = tmp_path / "packages" / "app"
    nested.mkdir(parents=True)
    (tmp_path / "config.env").write_text(f"GITHUB_TOKEN={_github_token()}\n", encoding="utf-8")
    _git(tmp_path, "add", "config.env")

    exit_code, output, _error = _run_native(["secrets", "scan", str(nested), "--staged", "--json"])

    payload = json.loads(output)
    assert exit_code == 0
    assert payload["truncated"] is False
    assert [finding["path"] for finding in payload["findings"]] == ["config.env"]


def test_relative_target_resolves_from_caller_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "config.env").write_text(f"GITHUB_TOKEN={_github_token()}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    exit_code = standalone_secrets_main(["scan", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert [finding["path"] for finding in json.loads(captured.out)["findings"]] == ["config.env"]


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
    assert all(set(rule) <= public_fields for rule in payload["rules"])
    assert all("pattern" not in rule and "candidate" not in rule for rule in payload["rules"])


def test_cli_rules_lists_detector_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = standalone_secrets_main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "HOL Guard Secrets detector" in captured.out
    assert "GitHub token" in captured.out


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


def test_cli_scan_json_returns_public_payload(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = standalone_secrets_main(["scan", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["schema"] == "guard-repository-secret-scan.v1"
    assert captured.err == ""


def test_cli_missing_target_returns_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = standalone_secrets_main(["scan", str(tmp_path / "missing")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error: secret scan target does not exist" in captured.err


def test_cli_fails_closed_without_native_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unavailable = SimpleNamespace(available=False, compatible=False, identity=None, capabilities=None)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: unavailable)

    exit_code = standalone_secrets_main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "requires the Guard native runtime" in captured.err


_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Guard refuses Git hook management off POSIX")


@_POSIX_ONLY
def test_hook_install_chains_and_uninstall_restores_existing_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    original = b"#!/bin/sh\necho existing-hook\n"
    hook.write_bytes(original)
    hook.chmod(0o755)

    exit_code, output, error = _run_native(["secrets", "install-hook", str(tmp_path), "--json"])
    assert (exit_code, error) == (0, "")
    assert json.loads(output) == {
        "chained_existing": True,
        "hook": "git-hooks/pre-commit",
        "schema": "guard-secrets-hook.v1",
        "status": "installed",
    }
    assert hook.with_name("pre-commit.hol-guard-user").read_bytes() == original
    content = hook.read_text(encoding="utf-8")
    assert "HOL_GUARD_SECRETS_PRE_COMMIT_V1" in content
    assert "hol-guard secrets scan --staged --fail-on-findings" in content

    exit_code, output, error = _run_native(["secrets", "install-hook", str(tmp_path)])
    assert (exit_code, error) == (0, "")
    assert "pre-commit hook installed: already_installed (git-hooks/pre-commit)" in output
    assert "Existing pre-commit behavior is preserved" in output

    exit_code, output, error = _run_native(["secrets", "uninstall-hook", str(tmp_path)])
    assert (exit_code, error) == (0, "")
    assert "pre-commit hook uninstalled: restored" in output
    assert hook.read_bytes() == original
    assert hook.stat().st_mode & 0o100
    assert not hook.with_name("pre-commit.hol-guard-user").exists()


@_POSIX_ONLY
def test_hook_install_refusal_returns_two(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _git(tmp_path, "config", "core.hooksPath", ".custom-hooks")

    exit_code, output, error = _run_native(["secrets", "install-hook", str(tmp_path)])

    assert exit_code == 2
    assert output == ""
    assert "custom core.hooksPath" in error


def test_interrupt_stops_native_scan_before_propagating(monkeypatch: pytest.MonkeyPatch) -> None:
    import _thread
    import threading

    from codex_plugin_scanner.guard import codex_hook_launch_runtime
    from codex_plugin_scanner.guard.secrets import cli as secrets_cli

    stopped = threading.Event()

    def fake_run(command: object, *, stop_event: threading.Event, **options: object) -> object:
        threading.Timer(0.3, _thread.interrupt_main).start()
        assert stop_event.wait(10)
        stopped.set()
        return SimpleNamespace(returncode=None)

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", fake_run)
    with pytest.raises(KeyboardInterrupt):
        secrets_cli._run_interruptibly(("runtime",), input_text="{}")
    assert stopped.is_set()
