"""Repository-level pytest safeguards for process-isolated regressions."""

from __future__ import annotations

import multiprocessing

import pytest

_PACKAGE_SHIM_SQLITE_LOCK_TEST = (
    "tests/test_guard_package_shims.py::test_package_manager_shim_waits_out_transient_store_writer_lock"
)


@pytest.fixture(autouse=True)
def _spawn_package_shim_sqlite_lock_holder(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid forking the SQLite lock holder from pytest's multithreaded process."""
    if request.node.nodeid != _PACKAGE_SHIM_SQLITE_LOCK_TEST:
        return

    context = multiprocessing.get_context("spawn")
    module = request.node.module
    monkeypatch.setattr(module, "Event", context.Event)
    monkeypatch.setattr(module, "Process", context.Process)
