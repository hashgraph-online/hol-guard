from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_mode import python_oracle_enabled, shadow_comparison_enabled
from codex_plugin_scanner.guard.native_runtime import native_mode
from codex_plugin_scanner.guard.store import GuardStore

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "python_hook_semantic_callgraph_gate.py"
SPEC = importlib.util.spec_from_file_location("python_hook_semantic_callgraph_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _copy_sources(root: Path) -> None:
    for relative in MODULE._PRODUCTION_FILES:
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def test_production_hook_callgraph_has_no_python_semantic_reachability() -> None:
    assert MODULE._graph_failures(ROOT) == []


def test_callgraph_rejects_semantic_import_in_worker(tmp_path: Path) -> None:
    _copy_sources(tmp_path)
    worker = tmp_path / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = worker.read_text(encoding="utf-8")
    marker = "from ..native_hook_edge import review_raw_hook_native\n"
    assert marker in source
    worker.write_text(
        source.replace(marker, marker + "from ..runtime.hook_review_engine import HookReviewEngine\n", 1),
        encoding="utf-8",
    )

    failures = MODULE._graph_failures(tmp_path)

    assert any("hook_worker.py" in failure and "semantic hook evaluator" in failure for failure in failures)


def test_callgraph_rejects_semantic_call_in_worker_entrypoint(tmp_path: Path) -> None:
    _copy_sources(tmp_path)
    worker = tmp_path / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = worker.read_text(encoding="utf-8")
    marker = "            return self._review_native_edge(\n"
    assert marker in source
    worker.write_text(source.replace(marker, "            return evaluate_command(\n", 1), encoding="utf-8")

    failures = MODULE._graph_failures(tmp_path)

    assert any("review_http_payload" in failure and "semantic hook evaluator" in failure for failure in failures)


def test_absent_or_invalid_oracle_never_selects_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.delenv("HOL_GUARD_PYTHON_ORACLE", raising=False)
    monkeypatch.delenv("HOL_GUARD_TEST_MODE", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_DIAGNOSTIC", raising=False)
    assert python_oracle_enabled() is False
    assert native_mode() == "off"

    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "not-a-flag")
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    assert python_oracle_enabled() is False


def test_production_off_returns_fail_safe_without_constructing_oracle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.delenv("HOL_GUARD_PYTHON_ORACLE", raising=False)
    monkeypatch.delenv("HOL_GUARD_TEST_MODE", raising=False)
    monkeypatch.setattr(HookWorker, "_test_python_oracle_factory", None)
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))

    result = worker.review_http_payload(
        payload={"hook_event_name": "PostToolUse", "tool_response": "safe"},
        params={},
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path,
    )

    assert result["continue"] is True
    assert result["reason_code"] == "native_hook_disabled"
    assert worker.test_oracle is None


def test_auto_never_constructs_test_oracle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.delenv("HOL_GUARD_PYTHON_ORACLE", raising=False)
    monkeypatch.delenv("HOL_GUARD_TEST_MODE", raising=False)

    def fail_factory(_worker: HookWorker) -> object:
        raise AssertionError("the production native worker must not construct a Python oracle")

    monkeypatch.setattr(HookWorker, "_test_python_oracle_factory", fail_factory)
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))

    assert worker.test_oracle is None


def test_shadow_comparison_requires_explicit_non_production_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "shadow")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.delenv("HOL_GUARD_NATIVE_DIAGNOSTIC", raising=False)

    assert shadow_comparison_enabled() is False
