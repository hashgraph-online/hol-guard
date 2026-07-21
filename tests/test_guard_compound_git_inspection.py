from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(command: str, *, home: Path) -> GuardArtifact | None:
    return _hook_runtime_artifact(
        harness="pi",
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


def test_compound_git_refresh_and_inspection_is_evaluated_as_one_unit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    artifact = _artifact(
        f"cd {workspace} && git -C repository fetch origin main 2>&1 | tail -5 "
        '&& echo "---ORIGIN---" && git -C repository log origin/main -1 --oneline '
        '&& echo "---STATUS---" && git -C repository status --short | head -20',
        home=home,
    )

    assert artifact is None


@pytest.mark.parametrize("repository", ("projects/repository", "./projects/repository", "."))
def test_compound_git_inspection_accepts_bounded_relative_repository_paths(
    tmp_path: Path,
    repository: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "projects" / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && git -C {repository} status --short | head -20", home=home) is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "git -C repository reset --hard origin/main",
        "git -C repository fetch origin main:refs/heads/main",
        "git -C ../outside fetch origin main",
        "git -C projects/../../outside status --short",
        "git -C /outside status --short",
        "git -C ~/outside status --short",
        "git -C projects/$TARGET status --short",
        "git -C repository status --short | sh",
        "git -C repository status --short > report.txt",
    ),
)
def test_compound_git_recovery_keeps_ambiguous_or_mutating_commands_guarded(
    tmp_path: Path,
    suffix: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {suffix}", home=home) is not None


def test_compound_git_recovery_rejects_dynamic_or_preceding_execution(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact("cd $TARGET && git -C repository fetch origin main", home=home) is not None
    assert (
        _artifact(
            f"printf ready && cd {workspace} && git -C repository status --short",
            home=home,
        )
        is not None
    )
