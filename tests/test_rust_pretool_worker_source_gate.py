from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.rust_pretool_no_python_gate import _worker_failures

_ROOT = Path(__file__).resolve().parents[1]
_DAEMON = Path("src/codex_plugin_scanner/guard/daemon")


def test_current_native_worker_delegation_is_fenced() -> None:
    assert _worker_failures(_ROOT) == []


@pytest.mark.parametrize(
    ("original", "replacement", "expected"),
    (
        (
            "with native_review_fence(",
            "with unrelated_context(",
            "delegation is not inside its authority fence",
        ),
        (
            "self._review_native_edge_with_snapshot(",
            "self._unverified_edge_with_snapshot(",
            "delegation is not inside its authority fence",
        ),
        (
            "self._review_raw_hook_native(",
            "self._python_evaluator(",
            "snapshot helper does not invoke the native hook edge",
        ),
    ),
)
def test_gate_rejects_a_broken_native_chain(tmp_path: Path, original: str, replacement: str, expected: str) -> None:
    target = tmp_path / _DAEMON
    target.mkdir(parents=True)
    for name in ("hook_worker.py", "hook_worker_native.py"):
        source = (_ROOT / _DAEMON / name).read_text()
        if name == "hook_worker_native.py":
            assert source.count(original) == 1
            source = source.replace(original, replacement)
        (target / name).write_text(source)
    assert any(expected in failure for failure in _worker_failures(tmp_path))
