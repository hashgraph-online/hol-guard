from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "rust_io_ownership_gate.py"
SPEC = importlib.util.spec_from_file_location("rust_io_ownership_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _copy_gate_sources(root: Path) -> None:
    paths = {spec.path for spec in MODULE.ROOTS} | {
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    }
    for relative in paths:
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def test_gate_inventories_reachable_io_and_passes_current_sources() -> None:
    report = MODULE.validate(ROOT)

    assert report["schema"] == "hol-guard.decision-critical-io.v1"
    assert report["status"] == "passed"
    assert report["inventory_total"] >= len(report["inventory"])
    assert report["inventory"]
    assert all(item["reachable"] for item in report["inventory"])
    categories = {item["category"] for item in report["inventory"]}
    all_categories = set(report["inventory_by_category"])
    assert "transport_identity" in categories
    assert "asynchronous_policy" in categories
    assert "compatibility_only" in all_categories
    assert "unclassified_python_io" not in categories
    assert "unclassified_python_content_io" not in categories


def test_gate_rejects_python_content_read_on_native_edge(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    edge = tmp_path / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    source = edge.read_text(encoding="utf-8")
    marker = "    status = native_runtime_status()\n"
    assert marker in source
    edge.write_text(source.replace(marker, marker + '    open("source.rs")\n', 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"reachable unclassified Python I/O"):
        MODULE.validate(tmp_path)


def test_gate_rejects_native_branch_semantic_fallback(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    worker = tmp_path / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = worker.read_text(encoding="utf-8")
    marker = "            return self._review_native_edge(\n"
    assert marker in source
    worker.write_text(source.replace(marker, "            return self.engine.review(\n", 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match="native edge return"):
        MODULE.validate(tmp_path)


def test_gate_rejects_synchronous_policy_compilation(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    publisher = tmp_path / "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    source = publisher.read_text(encoding="utf-8")
    marker = "            self._started = True\n"
    assert marker in source
    publisher.write_text(
        source.replace(marker, marker + "        self._compiled_effective_policy()\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="decision-time config or secret I/O"):
        MODULE.validate(tmp_path)
