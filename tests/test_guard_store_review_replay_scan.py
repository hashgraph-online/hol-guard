"""The native store owns the native workspace review replay scan cursor."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"
_BINDING = {"workspace_id": "workspace-1", "machine_installation_id": "installation-1"}


def _key(store: GuardStore) -> str:
    return f"guard_cloud_review_native_workspace_review_replay:scan:{store.guard_source}"


def test_full_batch_advances_and_a_short_batch_finishes_the_snapshot(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.native_workspace_review_replay_scan(binding=_BINDING) == (None, None)

    state = store.record_native_workspace_review_replay_scan(
        binding=_BINDING,
        request_ids=["request-01", "request-02"],
        limit=2,
        through_request_id="request-09",
        changed_at=_NOW,
    )

    assert state["cursor"] == "request-02"
    assert store.get_sync_payload(_key(store)) == state
    assert store.native_workspace_review_replay_scan(binding=_BINDING) == ("request-02", "request-09")
    assert store.native_workspace_review_replay_scan(binding={"workspace_id": "other"}) == (None, None)

    store.record_native_workspace_review_replay_scan(
        binding=_BINDING,
        request_ids=["request-05"],
        limit=2,
        through_request_id="request-09",
        changed_at=_NOW,
    )

    assert store.native_workspace_review_replay_scan(binding=_BINDING) == (None, None)


def test_legacy_cursor_without_upper_bound_restarts(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_key(store), {"binding": _BINDING, "cursor": "request-99"}, _NOW)

    assert store.native_workspace_review_replay_scan(binding=_BINDING) == (None, None)


@pytest.mark.parametrize(
    ("binding", "limit"),
    [({}, 2), ({"workspace_id": 1}, 2), (_BINDING, 0)],
)
def test_bad_scan_records_are_refused(tmp_path: Path, binding: dict[str, object], limit: int) -> None:
    store = GuardStore(tmp_path)

    with pytest.raises(ValueError):
        store.record_native_workspace_review_replay_scan(
            binding=binding,  # type: ignore[arg-type]
            request_ids=["request-01"],
            limit=limit,
            through_request_id="request-09",
            changed_at=_NOW,
        )
    assert store.get_sync_payload(_key(store)) is None
