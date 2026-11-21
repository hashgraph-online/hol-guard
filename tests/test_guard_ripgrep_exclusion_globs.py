from __future__ import annotations

from pathlib import Path

import pytest

from tests.live_hook_review_support import live_shell_review, quietly_allowed


def _quiet(command: str, *, home: Path, harness: str = "cursor") -> bool:
    cwd = home / "projects" / "current"
    cwd.mkdir(parents=True, exist_ok=True)
    return quietly_allowed(live_shell_review(command, home_dir=home, cwd=cwd, harness=harness, tool_name="Bash"))


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor", "grok"))
def test_harnesses_allow_compound_ripgrep_with_exclusion_and_type_globs(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src-tauri" / "src").mkdir(parents=True)
    (workspace / "src").mkdir()
    command = (
        f"cd {workspace} && "
        "rg -n 'navigate_dashboard_route|fn desktop_navigate' src-tauri/src --glob '!target' | head; "
        "rg -n 'navigate_dashboard|dashboard-route' src --include='*.ts*' -g '*.tsx' -g '*.ts' "
        "2>/dev/null | head -5"
    )

    assert _quiet(command, home=home, harness=harness)


@pytest.mark.parametrize(
    "unsafe_suffix",
    (
        "rg --pre 'sh -c touch${IFS}changed' value src",
        "rg -n token .env --glob '!target'",
        "rg -n value src --glob '!target'; git push origin main",
    ),
)
def test_ripgrep_exclusion_glob_does_not_hide_sensitive_or_mutating_effects(
    live_hook_root: Path,
    unsafe_suffix: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")

    assert not _quiet(f"cd {workspace} && {unsafe_suffix}", home=home)
