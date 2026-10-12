"""Unacknowledged local Watch settings cannot weaken native capacity denial."""

from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon
from tests.daemon_control_patching import patch_daemon_global


def test_capacity_failure_does_not_accept_local_watch_as_native_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = object.__new__(daemon._GuardDaemonHandler)
    handler.server = Mock(store=Mock(guard_home="fixture-home"))
    monkeypatch.setattr(handler, "_validated_fail_safe_hook_paths", lambda _params: (None, None))
    patch_daemon_global(
        monkeypatch,
        "load_guard_config",
        lambda *_args, **_kwargs: Mock(protection_posture="watch", mode="observe"),
    )
    # The mocked config-loader branch reads no real state.
    response = handler._runtime_hook_capacity_response({"hook_event_name": "PreToolUse"}, {}, default_harness="codex")
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
