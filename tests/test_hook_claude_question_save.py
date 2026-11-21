"""The integrity handoff used by the native Claude approval save."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import library_calls
from codex_plugin_scanner.guard.cli import desktop_library_call
from codex_plugin_scanner.guard.library_call_deadline import LIBRARY_CALL_DEADLINE
from codex_plugin_scanner.guard.store import GuardStore


def _finalize(home: Path, state: dict[str, object], *, timeout_seconds: float = 5.0) -> object:
    token = LIBRARY_CALL_DEADLINE.set(time.monotonic() + timeout_seconds)
    try:
        payload = json.dumps({"call": "hook.integrity_finalize", "args": {"next_control_state": state}}).encode()
        return library_calls.run_library_call(home, payload)
    finally:
        LIBRARY_CALL_DEADLINE.reset(token)


def test_integrity_finalize_reports_a_failed_control_state_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Store:
        def _finalize_policy_integrity_control_state(self, payload: object, *, deadline: float) -> bool:
            assert payload == {"generation": 1}
            assert deadline > time.monotonic()
            return False

    monkeypatch.setattr(library_calls, "GuardStore", lambda _guard_home: Store())
    assert _finalize(tmp_path, {"generation": 1}) == {"ok": {"finalized": False}}


def test_hook_finalization_uses_the_framed_deadline_after_opening_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    opened: list[Path] = []

    def open_store(guard_home: Path) -> object:
        opened.append(guard_home)
        clock[0] = 101.0
        return object()

    monkeypatch.setattr(library_calls, "GuardStore", open_store)
    monkeypatch.setattr(desktop_library_call.time, "monotonic", lambda: clock[0])
    payload = (
        b'{"id":1,"expires_in_ms":20,"call":"hook.integrity_finalize","args":{"next_control_state":{"generation":1}}}\n'
    )
    requests = iter([payload, b""])
    replies: list[bytes] = []
    assert desktop_library_call.serve_lines(tmp_path, lambda: next(requests), replies.append) == 0
    assert opened == [tmp_path]
    assert [json.loads(reply) for reply in replies] == [{"id": 1, "ok": {"finalized": False}}]


def test_hook_finalize_rejects_a_stale_generation_and_commits_the_prepared_one(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = native_approval_reuse_runtime
    store = GuardStore(home, prime_policy_integrity=False)
    current = {"version": 1, "generation": 8, "pending_generation": 9, "cutover_complete": True}
    writes: list[dict[str, object]] = []

    def read(*, strict: bool) -> dict[str, object]:
        assert strict is True
        return current

    def write(state: dict[str, object]) -> bool:
        writes.append(state)
        return True

    monkeypatch.setattr(store, "_read_policy_integrity_control_state_uncached", read)
    monkeypatch.setattr(store, "_store_policy_integrity_control_state", write)
    monkeypatch.setattr(library_calls, "GuardStore", lambda _guard_home: store)

    def finalize(generation: int, *, remaining_seconds: float = 5.0) -> object:
        return _finalize(
            home, {**current, "generation": generation, "pending_generation": None}, timeout_seconds=remaining_seconds
        )

    assert finalize(7) == {"ok": {"finalized": False}}
    assert finalize(9, remaining_seconds=0.0) == {"ok": {"finalized": False}}
    with ThreadPoolExecutor(max_workers=1) as executor, store.hold_policy_integrity_generation_lock():
        blocked = executor.submit(finalize, 9, remaining_seconds=0.05)
        assert blocked.result(timeout=2.0) == {"ok": {"finalized": False}}
    assert writes == []
    assert finalize(9) == {"ok": {"finalized": True}}
    assert writes == [{**current, "generation": 9, "pending_generation": None}]
