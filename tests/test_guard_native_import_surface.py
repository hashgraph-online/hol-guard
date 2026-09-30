from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"


def _run_import_probe(source: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(item for item in (str(_SOURCE_ROOT), existing) if item)
    return subprocess.run(
        [sys.executable, "-c", source],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_control_migration_module_imports_without_python_matchers() -> None:
    result = _run_import_probe(
        """
import sys
import codex_plugin_scanner.guard.runtime.command_dns_control_migration
forbidden = sorted(name for name in sys.modules if name.endswith("command_rules"))
if forbidden:
    raise SystemExit("unexpected matcher imports: " + repr(forbidden))
"""
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_store_and_inspection_imports_keep_legacy_matchers_out() -> None:
    result = _run_import_probe(
        """
import sys
import codex_plugin_scanner.guard.store
import codex_plugin_scanner.guard.runtime.command_activity_lifecycle
import codex_plugin_scanner.guard.runtime.command_inspection
from codex_plugin_scanner.guard.runtime.command_inspection import (
    command_extensions_payload,
    unavailable_command_inspection,
)

catalog = command_extensions_payload()
assert catalog["count"] > 0
assert unavailable_command_inspection("git status")["status"] == "native_unavailable"
forbidden = sorted(set(sys.modules) & {
    "codex_plugin_scanner.guard.runtime.command_rules",
    "codex_plugin_scanner.guard.runtime.command_builtin_rules",
    "codex_plugin_scanner.guard.runtime.command_dns_extensions",
    "codex_plugin_scanner.guard.runtime.command_managed_service_extensions",
    "codex_plugin_scanner.guard.runtime.command_remote_extensions",
    "codex_plugin_scanner.guard.runtime.command_remote_essh_extensions",
    "codex_plugin_scanner.guard.runtime.command_blitcp_extensions",
    "codex_plugin_scanner.guard.runtime.command_github_rules",
    "codex_plugin_scanner.guard.runtime.command_ollama_extensions",
})
if forbidden:
    raise SystemExit("unexpected matcher imports: " + repr(forbidden))
"""
    )
    assert result.returncode == 0, result.stderr or result.stdout
