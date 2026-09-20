"""Untimed fresh-process controls for the public scanner's lazy export."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "src"


def _fresh_process(code: str) -> None:
    bootstrap = f"import sys; sys.path.insert(0, {str(_SOURCE)!r})\n"
    completed = subprocess.run(
        [sys.executable, "-B", "-I", "-c", bootstrap + textwrap.dedent(code)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


@pytest.mark.parametrize(
    "module",
    [
        "codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge",
        "codex_plugin_scanner.guard.adapters.codex_daemon_hook_bridge",
    ],
    ids=["claude-bridge", "codex-bridge"],
)
def test_bridge_import_does_not_initialize_scanning_checks(module: str) -> None:
    _fresh_process(
        f"""
        import importlib
        importlib.import_module({module!r})
        assert "codex_plugin_scanner.scanner" not in sys.modules
        assert not any(name.startswith("codex_plugin_scanner.checks.") for name in sys.modules)
        """
    )


def test_public_scan_export_keeps_function_identity_signature_and_pickle() -> None:
    _fresh_process(
        """
        import inspect
        import pickle
        import codex_plugin_scanner as package
        assert "codex_plugin_scanner.scanner" not in sys.modules
        assert "scan_plugin" not in vars(package)
        assert "scan_plugin" in dir(package)
        assert "codex_plugin_scanner.scanner" not in sys.modules
        from codex_plugin_scanner import scan_plugin
        from codex_plugin_scanner.scanner import scan_plugin as implementation
        assert scan_plugin is implementation is package.scan_plugin
        assert vars(package)["scan_plugin"] is implementation
        assert inspect.signature(scan_plugin) == inspect.signature(implementation)
        assert pickle.loads(pickle.dumps(scan_plugin)) is implementation
        """
    )


def test_star_import_and_eager_model_version_exports_remain_compatible() -> None:
    _fresh_process(
        """
        import codex_plugin_scanner as package
        from codex_plugin_scanner import models, version
        expected = {
            "GRADE_LABELS", "CategoryResult", "CheckResult", "Finding",
            "PackageSummary", "ScanOptions", "ScanResult", "Severity",
            "__version__", "get_grade", "scan_plugin",
        }
        assert set(package.__all__) == expected
        assert package.__version__ == version.__version__
        for name in expected - {"scan_plugin", "__version__"}:
            assert getattr(package, name) is getattr(models, name)
        assert "codex_plugin_scanner.scanner" not in sys.modules
        namespace = {}
        exec("from codex_plugin_scanner import *", namespace)
        assert set(namespace) - {"__builtins__"} == expected
        assert namespace["scan_plugin"] is package.scan_plugin
        for name in expected:
            assert namespace[name] is getattr(package, name)
        """
    )


def test_missing_attribute_does_not_load_scanner() -> None:
    _fresh_process(
        """
        import codex_plugin_scanner as package
        try:
            package.no_such_export
        except AttributeError as error:
            assert str(error) == "module 'codex_plugin_scanner' has no attribute 'no_such_export'"
        else:
            raise AssertionError("missing package attribute did not fail")
        assert "codex_plugin_scanner.scanner" not in sys.modules
        """
    )


def test_concurrent_first_access_resolves_the_same_function() -> None:
    _fresh_process(
        """
        import threading
        from concurrent.futures import ThreadPoolExecutor
        import codex_plugin_scanner as package
        assert "codex_plugin_scanner.scanner" not in sys.modules
        barrier = threading.Barrier(4)
        def resolve(_index):
            barrier.wait(timeout=10)
            return package.scan_plugin
        with ThreadPoolExecutor(max_workers=4) as pool:
            functions = list(pool.map(resolve, range(4)))
        from codex_plugin_scanner.scanner import scan_plugin as implementation
        assert all(function is implementation for function in functions)
        assert package.scan_plugin is implementation
        """
    )


def test_deferred_import_error_propagates_without_caching_and_can_recover() -> None:
    _fresh_process(
        """
        import builtins
        import codex_plugin_scanner as package
        original_import = builtins.__import__
        failure = ImportError("controlled scanner import failure")
        def reject_scanner(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "scanner" and level == 1:
                raise failure
            return original_import(name, globals, locals, fromlist, level)
        builtins.__import__ = reject_scanner
        try:
            try:
                package.scan_plugin
            except ImportError as error:
                assert error is failure
            else:
                raise AssertionError("scanner import failure was suppressed")
            assert "scan_plugin" not in vars(package)
            assert "codex_plugin_scanner.scanner" not in sys.modules
        finally:
            builtins.__import__ = original_import
        from codex_plugin_scanner.scanner import scan_plugin as implementation
        assert package.scan_plugin is implementation
        """
    )


def test_package_reload_resolves_the_reloaded_scanner_function() -> None:
    _fresh_process(
        """
        import importlib
        import pickle
        import codex_plugin_scanner as package
        original = package.scan_plugin
        import codex_plugin_scanner.scanner as scanner
        importlib.reload(scanner)
        assert scanner.scan_plugin is not original
        assert package.scan_plugin is original
        importlib.reload(package)
        assert package.scan_plugin is scanner.scan_plugin
        assert pickle.loads(pickle.dumps(package.scan_plugin)) is scanner.scan_plugin
        """
    )


def test_explicit_export_monkeypatch_is_preserved_until_package_reload() -> None:
    _fresh_process(
        """
        import importlib
        import codex_plugin_scanner as package
        original = package.scan_plugin
        replacement = object()
        package.scan_plugin = replacement
        from codex_plugin_scanner import scan_plugin as imported
        assert imported is replacement
        assert package.scan_plugin is replacement
        importlib.reload(package)
        assert package.scan_plugin is original
        """
    )
