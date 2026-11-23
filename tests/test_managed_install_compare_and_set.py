"""The managed-install transition rows go through the runtime's compare and write."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_owned
from codex_plugin_scanner.guard.store_cloud_events import StoreCloudEventsMixin


class _Store(StoreCloudEventsMixin):
    def __init__(self, answers: dict[str, object]) -> None:
        self.guard_home = Path("guard-home")
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, args))
        return self.answers[method]


_ROW: dict[str, object] = {
    "harness": "codex",
    "active": 1,
    "workspace": None,
    "manifest": {"b": 1, "a": [2]},
    "updated_at": "t1",
}


@pytest.fixture(autouse=True)
def _owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_owned, "require_codex_install_owner", lambda _home: None)


def test_rows_are_compared_before_the_mutation_and_written_after_it() -> None:
    store = _Store({"compare_managed_installs": True, "compare_and_set_managed_installs": True})
    order: list[str] = []
    changes = [("codex", (None,), _ROW)]

    assert store.compare_and_set_managed_installs(changes, before_mutation=lambda: order.append("mutate"))

    assert [method for method, _ in store.calls] == ["compare_managed_installs", "compare_and_set_managed_installs"]
    assert order == ["mutate"]
    sent = store.calls[1][1]["changes"][0]
    assert sent["allowed"] == [None]
    assert sent["replacement"] == {
        "harness": "codex",
        "active": True,
        "workspace": None,
        "manifest_json": '{"b": 1, "a": [2]}',
        "updated_at": "t1",
    }
    assert isinstance(store.calls[1][1]["now"], str)


def test_a_moved_row_skips_the_mutation() -> None:
    store = _Store({"compare_managed_installs": False})
    called: list[str] = []

    assert not store.compare_and_set_managed_installs(
        [("codex", (_ROW,), None)], before_mutation=lambda: called.append("mutate")
    )

    assert called == []
    assert [method for method, _ in store.calls] == ["compare_managed_installs"]


@pytest.mark.parametrize(
    "changes",
    [
        [("codex", (None,), None), ("codex", (None,), None)],
        [("codex", (), None)],
        [("cursor", (None,), _ROW)],
    ],
)
def test_invalid_targets_are_refused_before_the_runtime_is_asked(changes: list[Any]) -> None:
    store = _Store({})

    with pytest.raises(ValueError):
        store.compare_and_set_managed_installs(changes, before_mutation=lambda: None)

    assert store.calls == []
