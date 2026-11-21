"""The integrity handoff used by the native Claude approval save."""

from __future__ import annotations

from codex_plugin_scanner.guard.routes.hook_calls import hook_integrity_finalize


def test_integrity_finalize_reports_a_failed_control_state_write() -> None:
    class Store:
        def _finalize_policy_integrity_control_state(self, payload: object) -> bool:
            return False

    assert hook_integrity_finalize(Store(), {"next_control_state": {"generation": 1}}) == {"finalized": False}
