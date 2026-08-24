from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def _classify(command: str, cwd: Path):
    return extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=cwd)


def test_github_auth_switch_help_is_local_metadata() -> None:
    assessment = classify_github_cli(("auth", "switch", "--help"))

    assert assessment.capability == "read_local"
    assert assessment.reason_code == "github.command.local-help"


@pytest.mark.parametrize(
    "command",
    (
        "gh api repos/example/project/check-runs/17/annotations 2>/dev/null | head -c 2000",
        "gh pr checks 17 --repo example/project >|/dev/null | head -c 10",
        "gh pr checks 17 --repo example/project 2>&1 | rg -v pass",
    ),
)
def test_proven_github_reads_accept_safe_output_filters(tmp_path: Path, command: str) -> None:
    assert _classify(command, tmp_path) is None


def test_rg_filter_with_runtime_preprocessor_config_still_requires_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RIPGREP_CONFIG_PATH", str(tmp_path / "ripgrep.conf"))

    match = _classify("gh pr checks 17 --repo example/project 2>&1 | rg -v pass", tmp_path)

    assert match is not None
    assert match.action_class == "Unverified GitHub command capability"


def test_github_output_redirect_to_workspace_file_still_requires_review(tmp_path: Path) -> None:
    match = _classify("gh pr view 17 > result.json", tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_bounded_ruff_format_module_invocation_is_routine(tmp_path: Path) -> None:
    source = tmp_path / "src" / "module.py"
    source.parent.mkdir()
    _ = source.write_text("value=1\n", encoding="utf-8")

    assert _classify("python3 -m ruff format src/module.py", tmp_path) is None


@pytest.mark.parametrize(
    "command",
    (
        "python3 -m ruff format ../outside.py",
        "python3 -m ruff format /outside.py",
        "python3 -m ruff format missing.py",
        "python3 -m ruff format .",
        "python3 -m ruff format src/module.py extra.py",
    ),
)
def test_unbounded_ruff_format_module_invocation_requires_review(tmp_path: Path, command: str) -> None:
    source = tmp_path / "src" / "module.py"
    source.parent.mkdir()
    _ = source.write_text("value=1\n", encoding="utf-8")

    match = _classify(command, tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"
