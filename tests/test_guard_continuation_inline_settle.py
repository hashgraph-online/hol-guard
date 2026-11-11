"""A live hook continuation settles in process, without starting a worker."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.continuation_runtime import continue_request_after_application
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_continuation_runtime import NOW, _live_codex_wait_metadata, _seed_request


def test_live_codex_hook_waits_without_starting_a_continuation_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "codex-live-no-spawn")
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-codex-live-no-spawn",
        metadata=_live_codex_wait_metadata(),
    )

    def refuse_process_start(_method: str) -> object:
        raise AssertionError("a live hook continuation must not start a process")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.continuation_contract.multiprocessing.get_context",
        refuse_process_start,
    )

    payload = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert payload["continuationStatus"] == "waiting"
    assert payload["continuationReason"] == "original_hook_waiting"
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
