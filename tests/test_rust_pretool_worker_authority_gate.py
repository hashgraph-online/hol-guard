"""Regression checks for the worker's extracted native-authority call graph."""

from __future__ import annotations

import runpy
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/ci/rust_pretool_no_python_gate.py"))
WORKER_DIR = Path("src/codex_plugin_scanner/guard/daemon")
WORKER_FILES = ("hook_worker.py", "hook_worker_native.py", "hook_worker_native_review.py")


@pytest.fixture
def worker_checkout(tmp_path: Path) -> Path:
    target = tmp_path / WORKER_DIR
    target.mkdir(parents=True)
    for name in WORKER_FILES:
        shutil.copyfile(ROOT / WORKER_DIR / name, target / name)
    return tmp_path


def test_current_worker_reaches_native_authority_through_review_helper() -> None:
    assert GATE["_worker_failures"](ROOT) == []


@pytest.mark.parametrize(
    ("filename", "call", "replacement", "expected"),
    [
        (
            "hook_worker_native.py",
            "return review_native_edge(",
            "return unavailable_review(",
            "HookWorkerNativeMixin._review_native_edge does not invoke review_native_edge",
        ),
        (
            "hook_worker_native_review.py",
            "return _review_native_edge_once(",
            "return unavailable_review(",
            "module.review_native_edge does not invoke _review_native_edge_once",
        ),
        (
            "hook_worker_native_review.py",
            "response, native_used = worker._review_native_edge_with_snapshot(",
            "response, native_used = worker.unavailable_review(",
            "module._review_native_edge_once does not invoke _review_native_edge_with_snapshot",
        ),
        (
            "hook_worker_native.py",
            "edge = self._review_raw_hook_native(",
            "edge = self.unavailable_review(",
            "HookWorkerNativeMixin._review_native_edge_with_snapshot does not invoke the native hook edge",
        ),
        (
            "hook_worker.py",
            "return review_raw_hook_native(",
            "return unavailable_review(",
            "HookWorker._review_raw_hook_native does not invoke review_raw_hook_native",
        ),
    ],
)
def test_missing_native_authority_link_fails_closed(
    worker_checkout: Path,
    filename: str,
    call: str,
    replacement: str,
    expected: str,
) -> None:
    path = worker_checkout / WORKER_DIR / filename
    source = path.read_text(encoding="utf-8")
    assert call in source
    path.write_text(source.replace(call, replacement, 1), encoding="utf-8")
    assert expected in GATE["_worker_failures"](worker_checkout)

