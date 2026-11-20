from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

from codex_plugin_scanner.guard.hook_review.hook_policy_admission import _native_managed_install_unmanaged


class _Store:
    def __init__(self, installs: dict[str, bool]) -> None:
        self.path = "/tmp/guard-test-store"
        self.installs = installs
        self.reads = 0
        self.revision = 0

    @contextmanager
    def connection_scope(self) -> Iterator[None]:
        yield

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        assert method == "hook_managed_install_admission"
        self.reads += 1
        harness = str(args["harness"])
        if harness in self.installs:
            unmanaged = self.installs[harness] is False
        else:
            unmanaged = any(active and name != harness for name, active in self.installs.items())
        return {"unmanaged": unmanaged, "revision": self.revision}


def _server(store: _Store) -> SimpleNamespace:
    return SimpleNamespace(store=store)


def test_active_answer_is_read_from_the_resident() -> None:
    store = _Store({"pi": True})
    assert _native_managed_install_unmanaged(store, "pi") is False
    assert store.reads == 1


def test_inactive_direct_row_is_unmanaged() -> None:
    store = _Store({"pi": False})
    assert _native_managed_install_unmanaged(store, "pi") is True


def test_other_active_harness_is_unmanaged() -> None:
    store = _Store({"claude-code": True})
    assert _native_managed_install_unmanaged(store, "pi") is True


def test_concurrent_reads_are_each_bounded_native_calls() -> None:
    store = _Store({"pi": True})
    workers = 8
    barrier = threading.Barrier(workers)
    answers: list[bool] = []

    def hook() -> None:
        barrier.wait()
        answers.append(_native_managed_install_unmanaged(store, "pi"))

    threads = [threading.Thread(target=hook) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert answers == [False] * workers
    assert store.reads == workers


def test_store_failure_stays_protected() -> None:
    class Broken:
        def _native_store_call(self, _method: str, _args: dict[str, object]) -> object:
            raise RuntimeError("resident unavailable")

    assert _native_managed_install_unmanaged(Broken(), "pi") is False
