from __future__ import annotations

import logging
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.local_runtime_fallbacks import best_effort_access_token
from codex_plugin_scanner.guard.store import GuardStore


class _UnexpectedResolverError(Exception):
    pass


def test_hermes_optional_token_logs_unexpected_resolver_failure_and_keeps_launch_viable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def _fail(_store: GuardStore) -> dict[str, object]:
        raise _UnexpectedResolverError("secret backend unavailable")

    monkeypatch.setattr(guard_runner, "_resolve_guard_sync_auth_context", _fail)
    with caplog.at_level(logging.INFO):
        assert guard_runner._resolve_hermes_guard_access_token(store) is None
    assert "_UnexpectedResolverError" in caplog.text
    assert "secret backend unavailable" not in caplog.text


def test_optional_token_boundary_does_not_catch_process_control_exceptions() -> None:
    def _interrupt() -> dict[str, object]:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        best_effort_access_token(_interrupt)
