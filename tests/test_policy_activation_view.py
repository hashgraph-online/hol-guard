"""The policy activation view keeps the stored text and refuses malformed replies."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard.store_policy_activation_view import read_policy_activation_view


class _Store:
    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.calls: list[tuple[str, Mapping[str, object]]] = []

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.calls.append((method, args))
        return self.reply


def test_the_view_keeps_stored_text_and_asks_each_key_once() -> None:
    store = _Store(
        {
            "sync_state": {"policy_bundle": '{"a": 1}', "policy_bundle_ack": None},
            "authority": {"revision": 7, "snapshot_digest": "digest"},
            "remote_rows": [["codex", "global"]],
        }
    )

    view = read_policy_activation_view(store, ("policy_bundle", "policy_bundle_ack", "policy_bundle"))

    assert store.calls == [("policy_activation_view", {"state_keys": ["policy_bundle", "policy_bundle_ack"]})]
    assert view.text("policy_bundle") == '{"a": 1}'
    assert view.text("policy_bundle_ack") is None
    assert view.authority == (7, "digest")
    assert view.remote_rows == (("codex", "global"),)
    with pytest.raises(KeyError):
        view.text("cloud_exceptions")


def test_a_missing_authority_snapshot_reads_as_none() -> None:
    view = read_policy_activation_view(
        _Store({"sync_state": {"policy": None}, "authority": None, "remote_rows": []}), ("policy",)
    )

    assert view.authority is None
    assert view.text("policy") is None


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {"sync_state": [], "authority": None, "remote_rows": []},
        {"sync_state": {"policy": 1}, "authority": None, "remote_rows": []},
        {"sync_state": {}, "authority": None, "remote_rows": [{}]},
        {"sync_state": {}, "authority": {"revision": True, "snapshot_digest": "d"}, "remote_rows": []},
        {"sync_state": {}, "authority": {"revision": 1}, "remote_rows": []},
    ],
)
def test_a_malformed_reply_is_refused(reply: object) -> None:
    with pytest.raises(RuntimeError, match="malformed policy activation view"):
        _ = read_policy_activation_view(_Store(reply), ("policy",))
