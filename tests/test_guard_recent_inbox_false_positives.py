from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact


def _artifact(command: str, *, home: Path, workspace: Path):
    return _hook_runtime_artifact(
        harness="codex",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".hol-guard",
        workspace=workspace,
    )


def test_command_lookup_does_not_execute_named_package_runner(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("viewport\n", encoding="utf-8")

    artifact = _artifact(
        "command -v npx >/dev/null 2>&1 && rg -n 'viewport' README.md | head -20",
        home=tmp_path,
        workspace=workspace,
    )

    assert artifact is None


def test_prefixed_command_lookup_does_not_execute_named_package_runner(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("viewport\n", encoding="utf-8")

    for lookup in (
        "CHECK=1 command -v npx",
        "time -p command -V npx",
        "time -p CHECK=1 command -v npx",
    ):
        artifact = _artifact(
            f"{lookup} >/dev/null 2>&1 && rg -n 'viewport' README.md | head -20",
            home=tmp_path,
            workspace=workspace,
        )
        assert artifact is None


def test_command_lookup_does_not_hide_actual_package_execution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    command = "command -v npx >/dev/null 2>&1 && npx --yes untrusted-package"

    assert _artifact(command, home=tmp_path, workspace=workspace) is not None


def test_prefixed_command_lookup_does_not_hide_shell_substitution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    for assignment in (
        "CHECK=`npx --yes untrusted-package`",
        "CHECK=$(npx --yes untrusted-package)",
        "CHECK=foo`npx --yes untrusted-package`",
    ):
        command = f"{assignment} command -v npx >/dev/null 2>&1"
        assert _artifact(command, home=tmp_path, workspace=workspace) is not None

    timed_lookup = "time -p command -v `npx --yes untrusted-package`"
    assert _artifact(timed_lookup, home=tmp_path, workspace=workspace) is not None

    for wrapper in ("env", "command", "sudo"):
        command = f"time -p command -v `{wrapper} npx --yes untrusted-package`"
        assert _artifact(command, home=tmp_path, workspace=workspace) is not None

    for outer_runner in ("npx --yes untrusted-package", "bunx untrusted-package"):
        command = f"CHECK=`date` {outer_runner}"
        assert _artifact(command, home=tmp_path, workspace=workspace) is not None
