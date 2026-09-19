"""Current observers can load when installed baseline diagnostics are absent."""

from __future__ import annotations

import builtins
import os
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


@pytest.mark.parametrize("entry", ["benchmark", "qualification"])
def test_script_imports_load_with_optional_diagnostic_module_absent(tmp_path: Path, entry: str) -> None:
    # Exercise the actual CLI import graph in an isolated child. Only this
    # optional module is made absent; this is no installed performance claim.
    root = Path(__file__).resolve().parents[1]
    script = """
import importlib, runpy, sys
from pathlib import Path
root = Path(sys.argv[1])
# Direct script execution puts scripts before the installed package and root.
# Supply the package from this checkout only to model the absent old observer.
sys.path[:0] = [str(root / 'scripts'), str(root / 'src'), str(root)]
# The current daemon requires diagnostics internally. Load it first so the
# absent optional observer models an older installed daemon's public surface.
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
sys.modules['codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics'] = None
if sys.argv[2] == 'qualification':
    runpy.run_path(str(root / 'scripts/qualify_guard_native.py'))
    runner = importlib.import_module('scripts.native_slo_qualification_run')
    assert callable(runner.run_block)
benchmark = importlib.import_module('scripts.bench_guard_native_installed_slo')
probe = benchmark._PROBE_MODULE
failure = importlib.import_module('ci.native_runtime.default_auto_failure')
routes = importlib.import_module('ci.native_runtime.default_auto_routes')
assert probe.DefaultAutoFailureCapture is failure.DefaultAutoFailureCapture
assert routes.observe_delivery is failure.observe_delivery
assert probe._evidence_failure_snapshot({}) is None
assert callable(benchmark._run_cold) and callable(benchmark._run_recovery)
print('import_boundary_complete')
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(root), entry],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "import_boundary_complete"


def test_real_benchmark_cli_loads_without_pythonpath(tmp_path: Path) -> None:
    # Do not add this checkout to the child path: the CLI must use the installed
    # package, with its script directory first, as in the native-wheel workflow.
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(root / "scripts/bench_guard_native_installed_slo.py"), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--runtime" in completed.stdout


def test_module_import_preserves_unrelated_entry_paths(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    script = """
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root / 'src'), str(root)]
original = list(sys.path)
from scripts import bench_guard_native_installed_slo
assert sys.path == original
assert callable(bench_guard_native_installed_slo._installed_hook_corpus)
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
