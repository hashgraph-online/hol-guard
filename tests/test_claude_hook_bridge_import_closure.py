from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HEAVY_MODULES = (
    "codex_plugin_scanner.guard.adapters.claude_code",
    "codex_plugin_scanner.guard.daemon.manager",
    "codex_plugin_scanner.guard.native_runtime",
    "codex_plugin_scanner.guard.native_context",
)


def test_claude_hook_bridge_import_stays_off_heavy_modules() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    program = (
        "import sys\n"
        "from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge\n"
        f"print([name for name in {HEAVY_MODULES!r} if name in sys.modules])\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        check=True,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(source_root), "PATH": ""},
    )
    assert result.stdout.strip() == "[]"
