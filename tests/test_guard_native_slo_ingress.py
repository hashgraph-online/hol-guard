from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from scripts import native_slo_session as native_slo_session_module
from scripts.native_slo_adapter import observation_reason_code


def test_hook_ingress_body_budget_remains_one_megabyte() -> None:
    assert _GuardDaemonHandler._MAX_BODY_BYTES == 1_000_000


def test_claude_slo_request_uses_authenticated_production_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def authenticated_response(**kwargs: object) -> str:
        captured.update(kwargs)
        return '{"continue":true,"decision":"allow"}'

    monkeypatch.setattr(
        native_slo_session_module,
        "authenticated_claude_hook_response",
        authenticated_response,
    )

    response = native_slo_session_module._request(
        cast(native_slo_session_module.GuardDaemonServer, cast(object, SimpleNamespace())),
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        harness="claude-code",
        request_payload={"hook_event_name": "PostToolUse"},
    )

    assert response["decision"] == "allow"
    assert captured["state_path"] == tmp_path / "guard-home" / "daemon-state.json"
    assert "workspace=" in str(captured["query"])


@pytest.mark.parametrize(
    "value", [None, {}, ["native_policy_not_ready"], "private@example.invalid", "native_private_detail"],
)
def test_slo_diagnostics_never_copy_unenumerated_response_details(value: object) -> None:
    assert observation_reason_code({"reason_code": value, "reason": "synthetic-private-detail"}) == "other"


def test_slo_observation_retains_a_bounded_failure_without_reclassifying_its_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder

    metrics = HookMetricsRecorder()
    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics)))
    session = object.__new__(native_slo_session_module.AdapterSession)
    session.daemon = daemon
    session.guard_home = tmp_path / "guard-home"
    session.workspace = tmp_path / "workspace"
    session._owner_thread_id = threading.get_ident()
    session._connection = None
    monkeypatch.setattr(native_slo_session_module, "_request", lambda *args, **kwargs: {
        "decision": "allow", "reason_code": "harness_not_managed", "reason": "synthetic-private-detail",
    })
    observation = session.observe("claude-code", "PreToolUse", "1k")
    assert observation.allowed
    assert observation.route == "native_fail_safe"
    assert not observation.overloaded
    assert observation.reason_code == "harness_not_managed"
    assert "synthetic-private-detail" not in repr(observation)
