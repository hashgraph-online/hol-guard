"""The policy publisher hands facts to the native daemon's admission route."""

import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.routes import hook_calls


@pytest.mark.parametrize("ready", [True, False])
def test_hook_prepare_reports_publisher_readiness(monkeypatch, tmp_path: Path, ready: bool) -> None:
    worker = SimpleNamespace(
        prepare_workspace_policy=Mock(return_value={"generation": 1} if ready else None),
        policy_snapshot_publisher=SimpleNamespace(
            last_error="native_client_timed_out",
            resident_failure_streak=lambda: 4,
        ),
        metrics=SimpleNamespace(record_route=Mock()),
    )
    monkeypatch.setattr(hook_calls, "_server", lambda *_args: SimpleNamespace(hook_worker=worker))
    workspace = tmp_path / "workspace"

    started = time.monotonic()
    result = hook_calls.hook_prepare(Mock(), {"workspace": str(workspace), "remaining_seconds": 2})
    worker.prepare_workspace_policy.assert_called_once()
    assert worker.prepare_workspace_policy.call_args.args == (workspace,)
    assert started + 2 <= worker.prepare_workspace_policy.call_args.kwargs["deadline"] <= time.monotonic() + 2

    if ready:
        assert result == {}
        worker.metrics.record_route.assert_not_called()
    else:
        assert result == {
            "fail_safe": {
                "reason": "HOL Guard could not prepare the native policy safely. "
                "This is usually temporary. Retry this action.",
                "reason_code": "native_policy_not_ready",
                "policy_failure": {"last_error": "native_client_timed_out", "resident_failure_streak": 4},
            }
        }
        worker.metrics.record_route.assert_called_once_with("native_fail_safe")
