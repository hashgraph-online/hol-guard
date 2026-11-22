"""The supply-chain bundle cache is read and written by the native store."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_WORKSPACE = "workspace-a"


def _response(version: str = "v1") -> dict[str, object]:
    return {
        "bundle": {
            "bundleVersion": version,
            "keyId": "key-1",
            "tier": "premium",
            "policyHash": "policy",
            "feedSnapshotHash": "feed",
            "scoringVersion": "s1",
            "rules": [{"id": "r1"}],
        },
        "payloadHash": "payload",
        "signature": "sig",
    }


def test_a_cached_response_reads_back_with_its_cached_at(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.cache_supply_chain_bundle(_WORKSPACE, _response(), "2026-11-22T00:00:00+00:00")

    assert store.get_cached_supply_chain_bundle(_WORKSPACE) == {
        **_response(),
        "cached_at": "2026-11-22T00:00:00+00:00",
    }
    assert store.get_cached_supply_chain_bundle("workspace-b") is None


def test_a_new_response_replaces_the_cached_one(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.cache_supply_chain_bundle(_WORKSPACE, _response("v1"), "t1")
    store.cache_supply_chain_bundle(_WORKSPACE, _response("v2"), "t2")

    cached = store.get_cached_supply_chain_bundle(_WORKSPACE)
    assert cached is not None
    assert cached["cached_at"] == "t2"
    assert cached["bundle"] == _response("v2")["bundle"]


def test_a_response_without_a_bundle_is_refused(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)

    with pytest.raises(ValueError, match="response must include a bundle object"):
        store.cache_supply_chain_bundle(_WORKSPACE, {"payloadHash": "p"}, "t")
    assert store.get_cached_supply_chain_bundle(_WORKSPACE) is None


def test_a_missing_bundle_field_is_refused(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    response = _response()
    bundle = response["bundle"]
    assert isinstance(bundle, dict)
    del bundle["keyId"]

    with pytest.raises(ValueError, match="keyId"):
        store.cache_supply_chain_bundle(_WORKSPACE, response, "t")


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {},
        {"page": "{}"},
        {"page": "{}", "length": 2, "cached_at": "t", "extra": 1},
        {"page": 7, "length": 2, "cached_at": "t"},
        {"page": "{}", "length": 2, "cached_at": None},
        {"page": "{}", "length": True, "cached_at": "t"},
        {"page": "{}", "length": -1, "cached_at": "t"},
        {"response_json": "{}", "cached_at": "t"},
    ],
)
def test_a_malformed_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="returned no answer"):
        store.get_cached_supply_chain_bundle(_WORKSPACE)


def test_a_stored_response_that_is_not_an_object_reads_as_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        return {"page": "[1]", "length": 3, "cached_at": "t"}

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_cached_supply_chain_bundle(_WORKSPACE) is None


def test_a_response_larger_than_one_reply_is_read_in_pages(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.cache_supply_chain_bundle(_WORKSPACE, _response(), "t1")
    large = _response()
    bundle = large["bundle"]
    assert isinstance(bundle, dict)
    bundle["rules"] = [{"id": f"r{index}", "note": "\u00e9" * 64} for index in range(40_000)]
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_supply_chain_bundle_cache set response_json = ? where workspace_id = ?",
            (json.dumps(large, ensure_ascii=False), _WORKSPACE),
        )

    cached = store.get_cached_supply_chain_bundle(_WORKSPACE)

    assert cached == {**large, "cached_at": "t1"}


def test_a_response_replaced_between_pages_is_read_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    answers = iter(
        [
            {"page": '{"bun', "length": 13, "cached_at": "t1"},
            {"page": "{}", "length": 2, "cached_at": "t2"},
            {"page": '{"a":', "length": 8, "cached_at": "t3"},
            {"page": "1}", "length": 8, "cached_at": "t3"},
            {"page": "", "length": 8, "cached_at": "t3"},
            {"page": "x", "length": 9, "cached_at": "t4"},
            {"page": "y", "length": 9, "cached_at": "t5"},
        ]
    )
    offsets: list[object] = []

    def native(_method: str, args: dict[str, object], **_kwargs: Any) -> object:
        offsets.append(args["offset"])
        return next(answers)

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="kept changing"):
        store.get_cached_supply_chain_bundle(_WORKSPACE)
    assert offsets == [0, 5, 0, 5, 7, 0, 1]


def test_a_steady_paged_response_is_joined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    answers = iter(
        [
            {"page": '{"a":', "length": 7, "cached_at": "t1"},
            {"page": "1}", "length": 7, "cached_at": "t1"},
        ]
    )

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        return next(answers)

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_cached_supply_chain_bundle(_WORKSPACE) == {"a": 1, "cached_at": "t1"}


def test_recovered_sign_in_metadata_falls_back_to_the_newest_cached_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.cache_supply_chain_bundle(" workspace-old ", _response(), "2026-11-01T00:00:00+00:00")
    store.cache_supply_chain_bundle(" workspace-new ", _response(), "2026-11-02T00:00:00+00:00")

    metadata = store._recover_oauth_workspace_metadata()  # pyright: ignore[reportPrivateUsage]

    assert metadata["workspace_id"] == "workspace-new"


def test_an_empty_cache_recovers_no_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)

    assert "workspace_id" not in store._recover_oauth_workspace_metadata()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("answer", [7, [], {"workspace_id": "w"}])
def test_a_malformed_newest_workspace_answer_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    store = GuardStore(tmp_path)

    def native(method: str, _args: object, **_kwargs: Any) -> object:
        assert method == "newest_supply_chain_bundle_workspace"
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="returned no answer"):
        store._recover_oauth_workspace_metadata()  # pyright: ignore[reportPrivateUsage]
