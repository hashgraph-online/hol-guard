from __future__ import annotations

from pathlib import Path

import pytest

from tests.live_hook_review_support import LIVE_REVIEWS_RETIRED_ALLOW, live_shell_review, quietly_allowed


def _quiet(command: str, *, home: Path, workspace: Path) -> bool:
    return quietly_allowed(live_shell_review(command, home_dir=home, cwd=workspace, guard_home=home / ".hol-guard"))


def test_command_lookup_does_not_execute_named_package_runner(live_hook_root: Path) -> None:
    workspace = live_hook_root / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("viewport\n", encoding="utf-8")

    quiet = _quiet(
        "command -v npx >/dev/null 2>&1 && rg -n 'viewport' README.md | head -20",
        home=live_hook_root,
        workspace=workspace,
    )

    assert quiet


@pytest.mark.parametrize(
    "lookup",
    (
        "CHECK=1 command -v npx",
        pytest.param("time -p command -V npx", marks=LIVE_REVIEWS_RETIRED_ALLOW),
        pytest.param("time -p CHECK=1 command -v npx", marks=LIVE_REVIEWS_RETIRED_ALLOW),
    ),
)
def test_prefixed_command_lookup_does_not_execute_named_package_runner(live_hook_root: Path, lookup: str) -> None:
    workspace = live_hook_root / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("viewport\n", encoding="utf-8")

    assert _quiet(
        f"{lookup} >/dev/null 2>&1 && rg -n 'viewport' README.md | head -20",
        home=live_hook_root,
        workspace=workspace,
    )


def test_command_lookup_does_not_hide_actual_package_execution(live_hook_root: Path) -> None:
    workspace = live_hook_root / "workspace"
    workspace.mkdir()

    command = "command -v npx >/dev/null 2>&1 && npx --yes untrusted-package"

    assert not _quiet(command, home=live_hook_root, workspace=workspace)


def test_prefixed_command_lookup_does_not_hide_shell_substitution(live_hook_root: Path) -> None:
    workspace = live_hook_root / "workspace"
    workspace.mkdir()

    for assignment in (
        "CHECK=`npx --yes untrusted-package`",
        "CHECK=$(npx --yes untrusted-package)",
        "CHECK=foo`npx --yes untrusted-package`",
    ):
        command = f"{assignment} command -v npx >/dev/null 2>&1"
        assert not _quiet(command, home=live_hook_root, workspace=workspace)

    timed_lookup = "time -p command -v `npx --yes untrusted-package`"
    assert not _quiet(timed_lookup, home=live_hook_root, workspace=workspace)

    for wrapper in ("env", "command", "sudo"):
        command = f"time -p command -v `{wrapper} npx --yes untrusted-package`"
        assert not _quiet(command, home=live_hook_root, workspace=workspace)

    for outer_runner in ("npx --yes untrusted-package", "bunx untrusted-package"):
        command = f"CHECK=`date` {outer_runner}"
        assert not _quiet(command, home=live_hook_root, workspace=workspace)
