"""Keep the source authority gate sensitive to detached native review paths."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path


def test_delegated_review_must_reach_snapshot_native_edge(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "review_delegation_gate", root / "scripts/ci/rust_pretool_no_python_gate.py"
    )
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    relative = Path("src/codex_plugin_scanner/guard/daemon")
    target = tmp_path / relative
    target.mkdir(parents=True)
    for name in ("hook_worker.py", "hook_worker_native.py", "hook_worker_native_review.py"):
        shutil.copyfile(root / relative / name, target / name)
    assert not gate._worker_failures(tmp_path)
    helper = target / "hook_worker_native_review.py"
    source = helper.read_text()
    assert "worker._review_native_edge_with_snapshot(" in source
    helper.write_text(source.replace("worker._review_native_edge_with_snapshot(", "worker._detached_native_edge("))
    assert "module._review_native_edge_once does not invoke _review_native_edge_with_snapshot" in (
        gate._worker_failures(tmp_path)
    )
