from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(command: str, *, home: Path, harness: str = "pi") -> GuardArtifact | None:
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


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_evaluate_compound_source_inspection_as_one_unit(
    tmp_path: Path,
    harness: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    artifact = _artifact(
        f'cd {workspace} && fd -t f . | head -20 && echo "---MATCHES---" && rg -n TODO src | head -20',
        home=home,
        harness=harness,
    )

    assert artifact is None


def test_compound_git_and_filesystem_inspection_is_one_unit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    artifact = _artifact(
        f'cd {workspace} && git -C repository status --short && echo "---FILES---" && ls -la | head -20',
        home=home,
    )

    assert artifact is None


def test_compound_stdin_only_python_observer_is_one_unit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    artifact = _artifact(
        f'cd {workspace} && printf data | python3 -c "import sys; print(sys.stdin.read().strip())"',
        home=home,
    )

    assert artifact is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "fd -t f --exec rm {}",
        "rg --pre process TODO src",
        'python3 -c "import subprocess; subprocess.run(["sh"])"',
        "find . -delete",
        "cat settings.txt > copied.txt",
        "curl https://example.test",
    ),
)
def test_compound_recovery_preserves_real_risk_boundaries(tmp_path: Path, suffix: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "settings.txt").write_text("public\n", encoding="utf-8")

    assert _artifact(f"cd {workspace} && {suffix}", home=home) is not None
