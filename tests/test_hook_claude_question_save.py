"""The integrity handoff used by the native Claude approval save."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import library_calls
from codex_plugin_scanner.guard.store import GuardStore


def test_integrity_finalize_reports_a_failed_control_state_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Store:
        def _finalize_policy_integrity_control_state(self, payload: object) -> bool:
            assert payload == {"generation": 1}
            return False

    monkeypatch.setattr(library_calls, "GuardStore", lambda _guard_home: Store())
    result = library_calls.run_library_call(
        tmp_path,
        b'{"call":"hook.integrity_finalize","args":{"next_control_state":{"generation":1}}}',
    )
    assert result == {"ok": {"finalized": False}}


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
        payload = json.dumps(
            {
                "call": "hook.integrity_finalize",
                "args": {
                    "remaining_seconds": remaining_seconds,
                    "next_control_state": {**current, "generation": generation, "pending_generation": None},
                },
            }
        ).encode()
        return library_calls.run_library_call(home, payload)

    assert finalize(7) == {"ok": {"finalized": False}}
    assert finalize(9, remaining_seconds=0.0) == {"ok": {"finalized": False}}
    with ThreadPoolExecutor(max_workers=1) as executor, store.hold_policy_integrity_generation_lock():
        blocked = executor.submit(finalize, 9, remaining_seconds=0.05)
        assert blocked.result(timeout=2.0) == {"ok": {"finalized": False}}
    assert writes == []
    assert finalize(9) == {"ok": {"finalized": True}}
    assert writes == [{**current, "generation": 9, "pending_generation": None}]
