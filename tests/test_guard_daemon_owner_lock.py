"""Cross-runtime daemon ownership coverage."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


@pytest.mark.skipif(os.name == "nt", reason="POSIX process inventory")
def test_procfs_process_inventory_entries_reach_the_ownership_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_line = shlex.join(
        (
            "python",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "daemon",
            "--serve",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--port",
            "4781",
        )
    )
    monkeypatch.setattr(manager.posix_processes, "posix_process_inventory", lambda: [(4242, command_line)])

    assert manager._guard_daemon_process_inventory_for_guard_home(tmp_path / "guard-home") == [(4242, 4781)]
