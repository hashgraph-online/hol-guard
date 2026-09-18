"""Current observers can load when installed baseline diagnostics are absent."""

from __future__ import annotations

import builtins
import subprocess
import sys
from pathlib import Path

import pytest

from ci.native_runtime import probe_native_default_auto as probe

_DIAGNOSTICS = "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics"


def test_absent_installed_diagnostics_remain_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, _DIAGNOSTICS, None)
    assert probe._evidence_failure_snapshot(None) is None
    assert probe._evidence_failure_snapshot({}) is None
    assert probe._evidence_failure_snapshot({"receipt_persistence/sqlite_busy": 2}) is None


def test_broken_diagnostic_dependency_is_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    original = builtins.__import__

    def import_module(name, *args, **kwargs):
        if name == _DIAGNOSTICS:
            raise ModuleNotFoundError("missing diagnostic dependency", name="missing_dependency")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_module)
    with pytest.raises(ModuleNotFoundError, match="missing diagnostic dependency"):
        probe._evidence_failure_snapshot({})


def test_real_benchmark_cli_loads_with_optional_diagnostic_module_absent(tmp_path: Path) -> None:
    # Exercise the actual CLI import graph in an isolated child. Only this
    # optional module is made absent; this is no installed performance claim.
    root = Path(__file__).resolve().parents[1]
    script = """
import runpy, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root / 'src'), str(root)]
# The current daemon requires diagnostics internally. Load it first so the
# absent optional observer models an older installed daemon's public surface.
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
sys.modules['codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics'] = None
sys.argv = [str(root / 'scripts/bench_guard_native_installed_slo.py'), '--help']
runpy.run_path(sys.argv[0], run_name='__main__')
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--runtime" in completed.stdout
