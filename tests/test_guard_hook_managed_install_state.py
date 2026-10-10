from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import hook_managed_install_state as state
from codex_plugin_scanner.guard.managed_install_revision import bump_managed_install_revision


class _Store:
    def __init__(self, installs: dict[str, bool]) -> None:
        self.path = "/tmp/guard-test-store"
        self.installs = installs
        self.reads = 0

    @contextmanager
    def connection_scope(self) -> Iterator[None]:
        yield

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        self.reads += 1
        if harness not in self.installs:
            return None
        return {"harness": harness, "active": self.installs[harness]}

    def list_managed_installs(self) -> list[dict[str, object]]:
        self.reads += 1
        return [{"harness": name, "active": active} for name, active in self.installs.items()]


@pytest.fixture(autouse=True)
def _clear_remembered_answers() -> Iterator[None]:
    state._protected_until.clear()
    yield
    state._protected_until.clear()


def _server(store: _Store) -> SimpleNamespace:
    return SimpleNamespace(store=store)


def test_protected_answer_is_remembered_between_hooks() -> None:
    store = _Store({"pi": True})
    server = _server(store)
    assert state._hook_harness_is_unmanaged(server, "pi") is False
    assert state._hook_harness_is_unmanaged(server, "pi") is False
    assert store.reads == 1


def test_local_managed_install_write_drops_remembered_answer() -> None:
    store = _Store({"pi": True})
    server = _server(store)
    assert state._hook_harness_is_unmanaged(server, "pi") is False
    store.installs["pi"] = False
    bump_managed_install_revision()
    assert state._hook_harness_is_unmanaged(server, "pi") is True


def test_remembered_answer_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store({"pi": True})
    server = _server(store)
    now = [1000.0]
    monkeypatch.setattr(state.time, "monotonic", lambda: now[0])
    assert state._hook_harness_is_unmanaged(server, "pi") is False
    now[0] += state._PROTECTED_ANSWER_TTL_SECONDS + 0.1
    store.installs["pi"] = False
    assert state._hook_harness_is_unmanaged(server, "pi") is True


def test_unmanaged_answer_is_never_remembered() -> None:
    store = _Store({"pi": False})
    server = _server(store)
    assert state._hook_harness_is_unmanaged(server, "pi") is True
    store.installs["pi"] = True
    assert state._hook_harness_is_unmanaged(server, "pi") is False


def test_other_active_harness_makes_unmanaged_without_remembering() -> None:
    store = _Store({"claude-code": True})
    server = _server(store)
    assert state._hook_harness_is_unmanaged(server, "pi") is True
    assert state._hook_harness_is_unmanaged(server, "pi") is True
    assert store.reads == 4


def test_store_failure_stays_protected_and_is_not_remembered() -> None:
    class _Broken(_Store):
        def get_managed_install(self, harness: str) -> dict[str, object] | None:
            raise RuntimeError("boom")

    store = _Broken({})
    server = _server(store)
    assert state._hook_harness_is_unmanaged(server, "pi") is False
    assert not state._protected_until
