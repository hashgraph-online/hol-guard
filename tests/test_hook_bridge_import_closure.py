from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

HEAVY_MODULES = (
    "codex_plugin_scanner.guard.claude_hook_entry",
    "codex_plugin_scanner.guard.native_daemon_manage",
    "codex_plugin_scanner.guard.native_runtime",
    "codex_plugin_scanner.guard.native_context",
    "codex_plugin_scanner.guard.config",
    "codex_plugin_scanner.models",
)


BRIDGES = ("bounded_cli_hook_bridge",)


@pytest.mark.parametrize("bridge", BRIDGES)
def test_hook_bridge_import_stays_off_heavy_modules(bridge: str) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    program = (
        "import sys\n"
        f"from codex_plugin_scanner.guard import {bridge}\n"
        f"print([name for name in {HEAVY_MODULES!r} if name in sys.modules])\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        check=True,
        timeout=60,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(source_root), "PATH": ""},
    )
    assert result.stdout.strip() == "[]"
