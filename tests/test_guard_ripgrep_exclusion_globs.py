from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


def _artifact(command: str, *, home: Path, harness: str = "cursor") -> object | None:
    return _hook_runtime_artifact(
        harness=harness,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=None,
    )


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor", "grok"))
def test_harnesses_allow_compound_ripgrep_with_exclusion_and_type_globs(
    tmp_path: Path,
    harness: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src-tauri" / "src").mkdir(parents=True)
    (workspace / "src").mkdir()
    command = (
        f"cd {workspace} && "
        "rg -n 'navigate_dashboard_route|fn desktop_navigate' src-tauri/src --glob '!target' | head; "
        "rg -n 'navigate_dashboard|dashboard-route' src --include='*.ts*' -g '*.tsx' -g '*.ts' "
        "2>/dev/null | head -5"
    )

    assert _artifact(command, home=home, harness=harness) is None


@pytest.mark.parametrize(
    "unsafe_suffix",
    (
        "rg --pre 'sh -c touch${IFS}changed' value src",
        "rg -n token .env --glob '!target'",
        "rg -n value src --glob '!target'; git push origin main",
    ),
)
def test_ripgrep_exclusion_glob_does_not_hide_sensitive_or_mutating_effects(
    tmp_path: Path,
    unsafe_suffix: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")

    assert _artifact(f"cd {workspace} && {unsafe_suffix}", home=home) is not None


@pytest.mark.parametrize(
    "command",
    (
        "rg --files --glob '!target' .env",
        "grep -r -e TOKEN --include .env .",
    ),
)
def test_direct_search_classification_keeps_sensitive_roots_and_positive_globs_guarded(
    tmp_path: Path,
    command: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)
    (workspace / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=workspace,
        home_dir=home,
    )
