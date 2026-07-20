from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import list_adapters
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_attention import (
    ApprovalAttentionCoordinator,
    request_max_severity,
    should_open_immediately,
)
from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime
from codex_plugin_scanner.guard.store import GuardStore


def _write_attention_config(guard_home: Path, *, delay: int = 20, immediate_severity: str = "critical") -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(
        "\n".join(
            (
                'approval_surface_policy = "attention-aware"',
                f"approval_browser_delay_seconds = {delay}",
                f'approval_browser_immediate_severity = "{immediate_severity}"',
                "desktop_notifications = false",
                "",
            )
        ),
        encoding="utf-8",
    )


def _queue_operation(
    root: Path,
    *,
    harness: str,
    severity: str,
) -> tuple[GuardStore, GuardSurfaceRuntime, dict[str, object]]:
    guard_home = root / "guard-home"
    workspace = root / "workspace"
    _write_attention_config(guard_home)
    store = GuardStore(guard_home)
    runtime = GuardSurfaceRuntime(store)
    session = runtime.start_session(
        harness=harness,
        surface="harness-adapter",
        workspace=str(workspace),
        client_name=f"{harness}-hook",
    )
    artifact = GuardArtifact(
        artifact_id=f"{harness}:project:action",
        name="Pending tool action",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / "settings.json"),
        metadata={},
    )
    result = runtime.queue_blocked_operation(
        session_id=str(session["session_id"]),
        operation_type="tool_call",
        harness=harness,
        metadata={"event": "tool_call"},
        detection={
            "harness": harness,
            "installed": True,
            "command_available": True,
            "config_paths": [artifact.config_path],
            "artifacts": [artifact.to_dict()],
        },
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "hash-123",
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "workspace": str(workspace),
                    "policy_action": "require-reapproval",
                    "changed_fields": ["command"],
                    "decision_v2_json": {
                        "action": "ask",
                        "signals": [{"severity": severity}],
                    },
                }
            ]
        },
        approval_center_url="http://127.0.0.1:5474",
        approval_surface_policy="attention-aware",
        open_key="tool-call",
        opener=lambda _url: True,
    )
    return store, runtime, result


def _schedule(
    store: GuardStore,
    runtime: GuardSurfaceRuntime,
    result: dict[str, object],
    *,
    now: list[float],
    opened_urls: list[str],
) -> ApprovalAttentionCoordinator:
    operation = result["operation"]
    requests = result["approval_requests"]
    assert isinstance(operation, dict)
    assert isinstance(requests, list)
    coordinator = ApprovalAttentionCoordinator(
        store=store,
        runtime=runtime,
        opener=lambda url: opened_urls.append(url) or True,
        clock=lambda: now[0],
        cooldown_seconds=0,
    )
    coordinator.schedule(
        operation_id=str(operation["operation_id"]),
        requests=[request for request in requests if isinstance(request, dict)],
        browser_url="http://127.0.0.1:5474/requests/pending",
    )
    return coordinator


def test_attention_policy_is_harness_agnostic(tmp_path: Path) -> None:
    for adapter in list_adapters():
        root = tmp_path / adapter.harness
        store, runtime, result = _queue_operation(root, harness=adapter.harness, severity="medium")
        now = [100.0]
        opened_urls: list[str] = []
        coordinator = _schedule(store, runtime, result, now=now, opened_urls=opened_urls)

        coordinator.process_due()
        assert opened_urls == []
        now[0] += 20
        coordinator.process_due()
        assert opened_urls == ["http://127.0.0.1:5474/requests/pending"]


def test_attention_policy_cancels_superseded_operation(tmp_path: Path) -> None:
    store, runtime, result = _queue_operation(tmp_path, harness="pi", severity="medium")
    now = [100.0]
    opened_urls: list[str] = []
    coordinator = _schedule(store, runtime, result, now=now, opened_urls=opened_urls)
    operation = result["operation"]
    assert isinstance(operation, dict)

    runtime.start_operation(
        session_id=str(operation["session_id"]),
        operation_type="safer_workaround",
        harness="pi",
    )
    now[0] += 20
    coordinator.process_due()

    assert opened_urls == []


def test_attention_policy_cancels_resolved_operation(tmp_path: Path) -> None:
    store, runtime, result = _queue_operation(tmp_path, harness="codex", severity="medium")
    now = [100.0]
    opened_urls: list[str] = []
    coordinator = _schedule(store, runtime, result, now=now, opened_urls=opened_urls)
    operation = result["operation"]
    assert isinstance(operation, dict)

    runtime.mark_operation_outcome(str(operation["operation_id"]), "completed")
    now[0] += 20
    coordinator.process_due()

    assert opened_urls == []


def test_attention_policy_opens_critical_request_without_delay(tmp_path: Path) -> None:
    store, runtime, result = _queue_operation(tmp_path, harness="pi", severity="critical")
    now = [100.0]
    opened_urls: list[str] = []
    coordinator = _schedule(store, runtime, result, now=now, opened_urls=opened_urls)

    coordinator.process_due()

    assert opened_urls == ["http://127.0.0.1:5474/requests/pending"]


def test_attention_policy_does_not_reopen_same_critical_request(tmp_path: Path) -> None:
    store, runtime, result = _queue_operation(tmp_path, harness="pi", severity="critical")
    now = [100.0]
    opened_urls: list[str] = []
    coordinator = _schedule(store, runtime, result, now=now, opened_urls=opened_urls)
    coordinator.process_due()

    operation = result["operation"]
    requests = result["approval_requests"]
    assert isinstance(operation, dict)
    assert isinstance(requests, list)
    coordinator.schedule(
        operation_id=str(operation["operation_id"]),
        requests=[request for request in requests if isinstance(request, dict)],
        browser_url="http://127.0.0.1:5474/requests/critical",
    )
    coordinator.process_due()
    assert opened_urls == ["http://127.0.0.1:5474/requests/pending"]

    now[0] += 5
    coordinator.process_due()
    assert opened_urls == ["http://127.0.0.1:5474/requests/pending"]
    request = requests[0]
    assert isinstance(request, dict)
    assert runtime.has_surface_opened(
        "approval-center",
        f"approval-request:{request['request_id']}",
    )


def test_attention_severity_uses_structured_signals() -> None:
    request = {
        "decision_v2_json": {
            "signals": [
                {"severity": "low"},
                {"severity": "high"},
                {"severity": "medium"},
            ]
        }
    }

    assert request_max_severity(request) == "high"
    assert should_open_immediately([request], "high") is True
    assert should_open_immediately([request], "critical") is False


@pytest.mark.parametrize("legacy_value", ["auto-open-once", None])
def test_attention_policy_is_the_loaded_default(tmp_path: Path, legacy_value: str | None) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    if legacy_value is not None:
        (guard_home / "config.toml").write_text(
            f'approval_surface_policy = "{legacy_value}"\n',
            encoding="utf-8",
        )

    from codex_plugin_scanner.guard.config import load_guard_config

    config = load_guard_config(guard_home)
    assert config.approval_surface_policy == "attention-aware"
    assert config.approval_browser_delay_seconds == 20
    assert config.approval_browser_immediate_severity == "critical"


def test_attention_settings_round_trip_and_validate(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.config import update_guard_settings

    guard_home = tmp_path / "guard-home"
    config = update_guard_settings(
        guard_home,
        {
            "approval_surface_policy": "attention-aware",
            "approval_browser_delay_seconds": 45,
            "approval_browser_immediate_severity": "high",
        },
    )

    assert config.approval_surface_policy == "attention-aware"
    assert config.approval_browser_delay_seconds == 45
    assert config.approval_browser_immediate_severity == "high"
    with pytest.raises(ValueError, match="between 0 and 300"):
        update_guard_settings(guard_home, {"approval_browser_delay_seconds": 301})
    with pytest.raises(ValueError, match="Invalid immediate"):
        update_guard_settings(guard_home, {"approval_browser_immediate_severity": "unknown"})
