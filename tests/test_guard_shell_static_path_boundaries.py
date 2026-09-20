from __future__ import annotations

from pathlib import Path, PureWindowsPath

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_static_safety


@pytest.mark.parametrize(
    ("token", "escapes"),
    (
        ("/etc/example.py", True),
        (r"\etc\example.py", True),
        (r"C:outside\example.py", True),
        ("C:example.py", True),
        ("src/example.py", False),
        ("example.py", False),
    ),
)
def test_windows_root_and_drive_relative_operands_cannot_supply_containment_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str, escapes: bool
) -> None:
    # Exercise Windows lexical semantics on every CI host. These decisions
    # precede filesystem inspection and must not depend on a current drive.
    monkeypatch.setattr(shell_static_safety, "Path", PureWindowsPath)

    assert shell_static_safety._shell_token_escapes_root(token, cwd=tmp_path, root=tmp_path) is escapes
