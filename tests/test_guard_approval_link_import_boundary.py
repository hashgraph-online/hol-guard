"""Signed hook links must not load approval/cloud management at worker startup."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_hook_link_import_does_not_load_approval_or_cli_orchestration() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import codex_plugin_scanner.guard.approval_hook_copy; "
            "assert 'codex_plugin_scanner.guard.approvals' not in sys.modules; "
            "assert 'codex_plugin_scanner.guard.cli.connect_flow' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
