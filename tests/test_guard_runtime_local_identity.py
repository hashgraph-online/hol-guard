"""The host name and private address a runtime session reports come from the runtime."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime import runner_native_authority


def test_the_runtime_reports_the_sync_time_and_a_source_for_each_field() -> None:
    identity, source = runner_native_authority.local_identity("2026-11-20T10:00:00+00:00")
    assert identity["lastSyncedAt"] == "2026-11-20T10:00:00+00:00"
    assert source["daemonId"] == "local-guard"
    for key in ("hostname", "ipAddress", "privateIpAddress"):
        assert (key in identity) == (key in source)
    assert not str(identity.get("ipAddress", "")).startswith("127.")


def test_a_session_without_a_runtime_answer_reports_only_its_sync_time(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unavailable(*_args: object, **_kwargs: object) -> object:
        raise NativeRunnerAuthorityError("unavailable")

    monkeypatch.setattr(runner_native_authority, "native_runner_authority", _unavailable)
    identity, source = guard_runner_module._cloud_local_identity(observed_at="2026-11-20T10:00:00+00:00")
    assert identity == {"lastSyncedAt": "2026-11-20T10:00:00+00:00"}
    assert source == {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
    }
