from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_presence
from codex_plugin_scanner.guard.native_policy_presence import (
    NativePolicyPresenceError,
    PolicyRowPresence,
    extension_control_authority_base,
    policy_row_presence,
)


@pytest.fixture(autouse=True)
def _provisioned(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    if "unprovisioned" not in request.node.name:
        monkeypatch.setattr(native_policy_presence, "_resident_provisioned", lambda _store: True)


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
    answer.setdefault("any_saved", any(answer[name] for name in ("local_policy", "remote_policy", "local_once")))
    return answer


def test_presence_reads_each_kind_from_the_native_store() -> None:
    store = _Store(_presence(remote_policy=True, policy_bundle=True))

    presence = policy_row_presence(store)

    assert store.calls == [("policy_row_presence", {})]
    assert presence == PolicyRowPresence(
        local_policy=False, remote_policy=True, local_once=False, policy_bundle=True, any_saved=True
    )
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
        _presence(any_saved=None),
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


class _UnprovisionedStore:
    """A home whose resident verifier key was never written."""

    def __init__(self, tmp_path: Any) -> None:
        self.guard_home = tmp_path / "guard-home"
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(
            "create table policy_decisions (source text);create table guard_local_once_approvals (id integer);"
        )

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        raise AssertionError(f"{method} would provision the resident and mint key material")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        yield self.connection


def test_an_unprovisioned_home_reads_presence_without_the_resident(tmp_path: Any) -> None:
    store = _UnprovisionedStore(tmp_path)

    assert policy_row_presence(store) == PolicyRowPresence(
        local_policy=False, remote_policy=False, local_once=False, policy_bundle=False, any_saved=False
    )

    store.connection.execute("insert into policy_decisions (source) values ('policy-bundle')")
    store.connection.execute("insert into guard_local_once_approvals (id) values (1)")
    presence = policy_row_presence(store)
    assert presence.remote_policy
    assert presence.policy_bundle
    assert presence.local_once
    assert not presence.local_policy
    assert presence.any_saved

    store.connection.execute("insert into policy_decisions (source) values ('local')")
    assert policy_row_presence(store).local_policy
