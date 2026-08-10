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


def test_literal_local_existence_probe_is_benign(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "example"
    workspace.mkdir(parents=True)

    assert _is_benign(
        f"test -e {workspace / 'candidate'} && echo exists || echo absent",
        cwd=workspace,
        home=home,
    )
    assert _is_benign(
        'test -e "my&file" && echo exists || echo absent',
        cwd=workspace,
        home=home,
    )


@pytest.mark.parametrize(
    "command",
    (
        "test -e $TARGET && echo exists || echo absent",
        "test -e /etc/passwd && echo exists || echo absent",
        "test -e ../outside && echo exists || echo absent",
        "test -e candidate && payload || echo absent",
        "test -f candidate && echo exists || echo absent",
        "test -e candidate; payload",
        "test -e candidate;id && echo exists || echo absent",
        "test -e <(id) && echo exists || echo absent",
        "test -e candidate&whoami && echo exists || echo absent",
        "test -e candidate|id && echo exists || echo absent",
    ),
)
def test_existence_probe_rejects_dynamic_widened_or_outside_commands(
    tmp_path: Path,
    command: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "example"
    workspace.mkdir(parents=True)

    assert not _is_benign(command, cwd=workspace, home=home)
