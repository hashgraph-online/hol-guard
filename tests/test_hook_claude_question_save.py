"""The integrity handoff used by the native Claude approval save."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import library_calls


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
