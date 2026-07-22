from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(
    command: str,
    *,
    home: Path,
    harness: str = "pi",
    workspace: Path | None = None,
) -> GuardArtifact | None:
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
        workspace=workspace,
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


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_recover_safe_inspection_after_cross_workspace_cd(
    tmp_path: Path,
    harness: str,
) -> None:
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    (inspected_workspace / "src").mkdir(parents=True)

    artifact = _artifact(
        f"cd {inspected_workspace} && grep -n TODO src/example.ts | head -20",
        home=home,
        harness=harness,
        workspace=active_workspace,
    )

    assert artifact is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_accept_safe_leading_delay_before_cross_workspace_inspection(
    tmp_path: Path,
    harness: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    assert (
        _artifact(
            f"sleep 30 && cd {workspace} && grep -n TODO src/example.ts | head -20",
            home=home,
            harness=harness,
        )
        is None
    )


@pytest.mark.parametrize(
    "delay_prefix",
    (
        "sleep 3601",
        "sleep 3600 && sleep 1",
        " && ".join(["sleep 1"] * 1100),
    ),
)
def test_compound_inspection_rejects_excessive_or_repeated_delays(tmp_path: Path, delay_prefix: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    command = f"{delay_prefix} && cd {workspace} && grep -n TODO src/example.ts | head -20"

    assert _artifact(command, home=home) is not None


@pytest.mark.parametrize("pattern", ("TODO", "component.property", "module-name.tsx"))
def test_compound_inspection_accepts_safe_stderr_suppression(tmp_path: Path, pattern: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && grep -rn {pattern} src 2>/dev/null | head -20", home=home) is None


@pytest.mark.parametrize("redirect", ("2>report.txt", "> report.txt", "< input.txt"))
def test_compound_inspection_keeps_file_redirection_guarded(tmp_path: Path, redirect: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && grep -rn TODO src {redirect} | head -20", home=home) is not None


def test_cross_workspace_recovery_preserves_mutating_command_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    inspected_workspace.mkdir(parents=True)

    assert (
        _artifact(
            f"cd {inspected_workspace} && git push origin main",
            home=home,
            workspace=active_workspace,
        )
        is not None
    )
    assert (
        _artifact(
            f"cd {inspected_workspace} && vitest run src/example.test.ts --maxWorkers=1",
            home=home,
            workspace=active_workspace,
        )
        is not None
    )


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
        f"cd {workspace} && printf data | {shlex.quote(sys.executable)} "
        + '-c "import sys; print(sys.stdin.read().strip())"',
        home=home,
    )

    assert artifact is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_keep_compound_destructive_commands_guarded(
    tmp_path: Path,
    harness: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    artifact = _artifact(
        f"cd {workspace} && printf ready && rm -rf ./generated-output",
        home=home,
        harness=harness,
    )

    assert artifact is not None
    assert artifact.metadata["action_class"] == "destructive shell command"


def test_compound_shell_syntax_check_is_inspection_only(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    script = workspace / "scripts" / "check.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n", encoding="utf-8")

    assert _artifact(f"cd {workspace} && bash -n scripts/check.sh && echo valid", home=home) is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "fd -t f --exec rm {}",
        "rg --pre process TODO src",
        'python3 -c "import subprocess; subprocess.run(["sh"])"',
        "find . -delete",
        "cat settings.txt > copied.txt",
        "cat /etc/example.py",
        "cat ../../../../outside/example.py",
        "cd / && cat /etc/example.py",
        "curl https://example.test",
        "bash scripts/check.sh",
        "bash -n ../outside.sh",
    ),
)
def test_compound_recovery_preserves_real_risk_boundaries(tmp_path: Path, suffix: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "settings.txt").write_text("public\n", encoding="utf-8")

    assert _artifact(f"cd {workspace} && {suffix}", home=home) is not None
