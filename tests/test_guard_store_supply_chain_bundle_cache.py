"""The supply-chain bundle cache is read and written by the native store."""

from __future__ import annotations

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
        {"response_json": "{}"},
        {"response_json": "{}", "cached_at": "t", "extra": 1},
        {"response_json": 7, "cached_at": "t"},
        {"response_json": "{}", "cached_at": None},
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
        return {"response_json": "[1]", "cached_at": "t"}

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_cached_supply_chain_bundle(_WORKSPACE) is None
