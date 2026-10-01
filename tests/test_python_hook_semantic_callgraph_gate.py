from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

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
