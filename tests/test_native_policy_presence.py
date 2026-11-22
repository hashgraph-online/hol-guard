from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_policy_presence import (
    NativePolicyPresenceError,
    PolicyRowPresence,
    extension_control_authority_base,
    policy_row_presence,
)


class _Store:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.calls.append((method, dict(args)))
        return self.answer


def _presence(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "local_policy": False,
        "remote_policy": False,
        "local_once": False,
        "policy_bundle": False,
    }
    answer.update(overrides)
    return answer


def test_presence_reads_each_kind_from_the_native_store() -> None:
    store = _Store(_presence(remote_policy=True, policy_bundle=True))

    presence = policy_row_presence(store)

    assert store.calls == [("policy_row_presence", {})]
    assert presence == PolicyRowPresence(local_policy=False, remote_policy=True, local_once=False, policy_bundle=True)
    assert presence.any_saved


def test_an_empty_store_has_no_saved_rows() -> None:
    assert not policy_row_presence(_Store(_presence())).any_saved
    assert policy_row_presence(_Store(_presence(local_once=True))).any_saved


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {},
        _presence(local_policy=1),
        _presence(local_policy="true"),
        {**_presence(), "extra": False},
        {key: value for key, value in _presence().items() if key != "policy_bundle"},
    ],
)
def test_a_malformed_presence_answer_is_refused(answer: object) -> None:
    with pytest.raises(NativePolicyPresenceError):
        policy_row_presence(_Store(answer))


def test_authority_base_is_empty_without_a_stored_snapshot() -> None:
    store = _Store(None)

    assert extension_control_authority_base(store) == {}
    assert store.calls == [("extension_control_authority_head", {})]


def test_authority_base_names_the_stored_snapshot() -> None:
    store = _Store({"revision": 7, "snapshot_digest": "abc"})

    assert extension_control_authority_base(store) == {"base_revision": 7, "base_snapshot_digest": "abc"}


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {},
        {"revision": "7", "snapshot_digest": "abc"},
        {"revision": True, "snapshot_digest": "abc"},
        {"revision": 7, "snapshot_digest": None},
        {"revision": 7, "snapshot_digest": "abc", "extra": 1},
    ],
)
def test_a_malformed_authority_head_is_refused(answer: object) -> None:
    with pytest.raises(NativePolicyPresenceError):
        extension_control_authority_base(_Store(answer))
