"""The integrity handoff used by the native Claude approval save."""

from __future__ import annotations

from pathlib import Path
from time import monotonic

import pytest

from codex_plugin_scanner.guard import library_calls
from codex_plugin_scanner.guard.native_claude_question_save import _FEATURE, _write_question
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.routes import policy_write_calls
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


def test_local_writer_holds_the_generation_lock_during_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = native_runtime_status()
    assert runtime.capabilities is not None and _FEATURE in runtime.capabilities.features
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    calls = 0

    def prepare(owner: GuardStore, _args: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        with (
            pytest.raises(TimeoutError, match="generation lock still held"),
            owner._hold_advisory_file_lock(
                path=owner.guard_home / "policy-integrity-generation.lock",
                timeout_seconds=0.1,
                poll_seconds=0.01,
                timeout_message="generation lock still held",
            ),
        ):
            pytest.fail("the writer released the lock before preparation")
        return {}

    monkeypatch.setattr(policy_write_calls, "integrity_begin", prepare)
    args = {"now": "2026-11-21T12:00:00Z"}
    with store.hold_policy_integrity_generation_lock():
        assert _write_question(store, args, monotonic() + 0.25) is None
    assert calls == 0
    assert _write_question(store, args, monotonic() + 3.0) is None
    assert calls == 1
