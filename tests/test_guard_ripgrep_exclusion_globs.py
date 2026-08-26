from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact


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
