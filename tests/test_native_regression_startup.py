"""Native startup must reuse one interpreter without weakening wheel qualification."""

from __future__ import annotations

import json
import os
import sys
import sysconfig
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from codex_plugin_scanner.guard.extension_builder.native_source_compiler import NativeSourceCompilerError
from scripts.ci import native_regression_shard as shard

ROOT = Path(__file__).resolve().parents[1]


def _installed_package(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    package = ModuleType("codex_plugin_scanner")
    package.__file__ = str(path)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner", package)


def _native_probes(monkeypatch: pytest.MonkeyPatch, identity: object, compiler: object) -> list[str]:
    calls: list[str] = []
    runtime = ModuleType("codex_plugin_scanner.guard.native_runtime")
    source = ModuleType("codex_plugin_scanner.guard.extension_builder.native_source_compiler")

    def status():
        calls.append("runtime")
        return SimpleNamespace(identity=identity)

    def find_compiler():
        calls.append("compiler")
        if compiler is None:
            raise NativeSourceCompilerError("packaged native resources are unavailable")
        return compiler

    monkeypatch.setattr(runtime, "native_runtime_status", status, raising=False)
    monkeypatch.setattr(source, "find_packaged_source_compiler", find_compiler, raising=False)
    monkeypatch.setattr(source, "NativeSourceCompilerError", NativeSourceCompilerError, raising=False)
    monkeypatch.setitem(sys.modules, runtime.__name__, runtime)
    monkeypatch.setitem(sys.modules, source.__name__, source)
    return calls


def test_startup_resolves_both_installed_binaries_in_the_execution_process(monkeypatch: pytest.MonkeyPatch) -> None:
    site = Path(sysconfig.get_paths()["purelib"])
    _installed_package(monkeypatch, site / "codex_plugin_scanner/__init__.py")
    binary = site / "runtime with spaces/hol-guard-runtime"
    compiler = site / "compiler with spaces/guard-command-source"
    calls = _native_probes(monkeypatch, SimpleNamespace(path=binary), compiler)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "untrusted-override")
    monkeypatch.setenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", "untrusted-compiler")

    shard._configure_installed_native()

    assert calls == ["runtime", "compiler"]
    assert os.environ["HOL_GUARD_NATIVE_BINARY"] == str(binary)
    assert os.environ["HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"] == str(compiler)


@pytest.mark.parametrize("missing", ["runtime", "compiler"])
def test_missing_installed_binary_fails_without_publishing_partial_overrides(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    site = Path(sysconfig.get_paths()["purelib"])
    _installed_package(monkeypatch, site / "codex_plugin_scanner/__init__.py")
    identity = None if missing == "runtime" else SimpleNamespace(path=site / "runtime")
    compiler = None if missing == "compiler" else site / "compiler"
    _native_probes(monkeypatch, identity, compiler)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "original-runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", "original-compiler")

    with pytest.raises(pytest.UsageError, match="installed wheel has no native"):
        shard._configure_installed_native()

    assert os.environ["HOL_GUARD_NATIVE_BINARY"] == "original-runtime"
    assert os.environ["HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"] == "original-compiler"


def test_startup_and_post_collection_both_reject_source_tree_imports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _installed_package(monkeypatch, tmp_path / "src/codex_plugin_scanner/__init__.py")
    calls = _native_probes(monkeypatch, SimpleNamespace(path=tmp_path / "runtime"), tmp_path / "compiler")

    with pytest.raises(pytest.UsageError, match="must import the installed wheel"):
        shard._configure_installed_native()
    with pytest.raises(pytest.UsageError, match="must import the installed wheel"):
        shard._AssertInstalled().pytest_collection_finish(None)
    assert calls == []


def _arguments(monkeypatch: pytest.MonkeyPatch, report: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "native_regression_shard.py",
            "--shard-index",
            "0",
            "--shard-count",
            "1",
            "--platform",
            "x86_64-unknown-linux-musl",
            "--report",
            str(report),
        ],
    )


def test_startup_failure_writes_a_failing_report_without_running_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = tmp_path / "reports/native.json"
    _arguments(monkeypatch, report)

    def fail() -> None:
        raise pytest.UsageError("installed wheel has no native runtime identity")

    def unexpected(*args, **kwargs):
        pytest.fail("pytest must not execute after failed installed-wheel validation")

    monkeypatch.setattr(shard, "_configure_installed_native", fail)
    monkeypatch.setattr(shard.pytest, "main", unexpected)

    assert shard.main() == int(pytest.ExitCode.USAGE_ERROR)
    evidence = json.loads(report.read_text())
    assert evidence["exit_code"] == int(pytest.ExitCode.USAGE_ERROR)
    assert evidence["collected_count"] == 0
    assert evidence["selected"] == []


def test_packaged_compiler_error_writes_failing_evidence_without_running_pytest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = Path(sysconfig.get_paths()["purelib"])
    _installed_package(monkeypatch, site / "codex_plugin_scanner/__init__.py")
    _native_probes(monkeypatch, SimpleNamespace(path=site / "runtime"), None)
    report = tmp_path / "native.json"
    _arguments(monkeypatch, report)

    def unexpected(*args, **kwargs):
        pytest.fail("pytest must not execute after compiler validation fails")

    monkeypatch.setattr(shard.pytest, "main", unexpected)
    assert shard.main() == int(pytest.ExitCode.USAGE_ERROR)
    evidence = json.loads(report.read_text())
    assert evidence["exit_code"] == int(pytest.ExitCode.USAGE_ERROR)
    assert evidence["collected_count"] == 0
    assert evidence["selected"] == []


@pytest.mark.parametrize("exit_code", [0, 1, 2, 3, 4, 5])
def test_execution_preserves_original_manifest_assertions_and_exit_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_code: int
) -> None:
    report = tmp_path / "native.json"
    _arguments(monkeypatch, report)
    calls: list[str] = []
    monkeypatch.setattr(shard, "_configure_installed_native", lambda: calls.append("configure"))

    def execute(arguments, *, plugins):
        assert calls == ["configure"]
        assert arguments == ["@" + str(shard.ROOT / "ci/native_runtime/regression-tests.txt"), "--durations=10"]
        assert isinstance(plugins[0], shard.NativeShard)
        assert isinstance(plugins[1], shard._AssertInstalled)
        plugins[0].all_nodes = ["tests/test_native.py::test_real_binary"]
        plugins[0].selected = list(plugins[0].all_nodes)
        calls.append("pytest")
        return exit_code

    monkeypatch.setattr(shard.pytest, "main", execute)

    assert shard.main() == exit_code
    assert calls == ["configure", "pytest"]
    assert json.loads(report.read_text())["exit_code"] == exit_code


def test_regression_action_does_not_spawn_duplicate_native_probes() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/native-regression/action.yml").read_text())
    step = next(
        item for item in action["runs"]["steps"] if item.get("name") == "Run the complete manifest's assigned shard"
    )
    assert step["run"].count("uv run --no-sync python") == 1
    assert "python -c" not in step["run"]
    assert "native_regression_shard.py" in step["run"]
    assert step["env"]["HOL_GUARD_TEST_USE_INSTALLED"] == "1"
    assert step["env"]["HOL_GUARD_NATIVE_REGRESSION"] == "1"
    assert not step.get("continue-on-error")
