from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


def _is_benign(command: str, *, cwd: Path, home: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=cwd,
        home_dir=home,
    )


def test_literal_workspace_directory_creation_is_benign(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "example"
    workspace.mkdir(parents=True)

    assert _is_benign("mkdir -p src assets .github/workflows", cwd=workspace, home=home)
    assert _is_benign(
        f'mkdir --parents "{home / "new project"}" {workspace / ".codex-plugin"}',
        cwd=workspace,
        home=home,
    )
    assert _is_benign(
        "mkdir -p ~/new-project/assets ~/new-project/.github/workflows",
        cwd=workspace,
        home=home,
    )


@pytest.mark.parametrize(
    "command",
    (
        "mkdir target",
        "mkdir -m 700 target",
        "mkdir -p --mode=700 target",
        "mkdir -p ../outside",
        "mkdir -p /etc/guard-test",
        "mkdir -p $TARGET",
        "mkdir -p target; id",
        "mkdir -p target |& id",
        "mkdir -p target >> output.log",
        "mkdir -p target >& output.log",
        "mkdir -p <(id)",
        "mkdir -p ~/.ssh/guard-test",
        "mkdir -p ~other/guard-test",
    ),
)
def test_directory_creation_rejects_widened_dynamic_or_sensitive_targets(
    tmp_path: Path,
    command: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "example"
    workspace.mkdir(parents=True)

    assert not _is_benign(command, cwd=workspace, home=home)
