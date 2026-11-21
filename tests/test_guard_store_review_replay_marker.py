"""The native store owns the native workspace review replay marker rules."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"
_BINDING = {"workspace_id": "workspace-1", "machine_installation_id": "installation-1"}
_AUTHORITY = {"authority_generation": 3, "authority_record_digest": "b" * 64}


def _key(store: GuardStore, request_id: str) -> str:
    digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
    return f"guard_cloud_review_native_workspace_review_replay:{store.guard_source}:request:{digest}"


def test_failed_probe_backs_off_and_is_not_due_until_retry(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    read = store.native_workspace_review_replay_marker("request-1", binding=_BINDING, now=_NOW)
    assert read == {"key": _key(store, "request-1"), "marker": None, "due": True}

    outcome = store.transition_native_workspace_review_replay_marker(
        "request-1", "probed", binding=_BINDING, now=_NOW, authority=None
    )

    assert outcome["action"] == "failed"
    marker = store.get_sync_payload(_key(store, "request-1"))
    assert isinstance(marker, dict)
    assert marker["attempts"] == 1
    assert marker["next_probe_at"] == "2026-09-27T12:02:00+00:00"
    assert not store.native_workspace_review_replay_marker("request-1", binding=_BINDING, now=_NOW)["due"]
    assert store.native_workspace_review_replay_marker("request-1", binding=_BINDING, now=_NOW, force_probe=True)["due"]


def test_requeue_seed_then_acceptance(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    outcome = store.transition_native_workspace_review_replay_marker(
        "request-1", "probed", binding=_BINDING, now=_NOW, authority=_AUTHORITY
    )
    assert outcome["action"] == "requeue"
    assert store.get_sync_payload(_key(store, "request-1")) is None
    seed = outcome["seed"]
    assert isinstance(seed, dict)

    store.transition_native_workspace_review_replay_marker(
        "request-1", "requeued", binding=_BINDING, now=_NOW, seed=seed, count=1
    )
    accepted = store.transition_native_workspace_review_replay_marker(
        "request-1", "accepted", binding=_BINDING, now=_NOW, authority=_AUTHORITY
    )

    assert accepted["result"] == "accepted"
    marker = store.get_sync_payload(_key(store, "request-1"))
    assert isinstance(marker, dict)
    assert marker["accepted"] is True
    assert marker["accepted_at"] == _NOW
    assert marker["requeued"] == 1


def test_bad_inputs_are_refused_without_a_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_now"):
        store.native_workspace_review_replay_marker("request-1", binding=_BINDING, now="2026-09-27T12:00:00")
    with pytest.raises(ValueError, match="invalid_step"):
        store.transition_native_workspace_review_replay_marker("request-1", "other", binding=_BINDING, now=_NOW)
    with pytest.raises(ValueError, match="invalid_seed"):
        store.transition_native_workspace_review_replay_marker(
            "request-1",
            "requeued",
            binding=_BINDING,
            now=_NOW,
            seed={"request_id": "request-2", "binding": _BINDING, "attempts": 1},
            count=1,
        )
    assert store.get_sync_payload(_key(store, "request-1")) is None
