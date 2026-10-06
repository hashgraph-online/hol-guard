"""CLI native-unavailable presentation for managed structured destinations."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_availability as availability
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _apply_native_edge_envelope_fields
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.runtime.structured_output_mediation import STRUCTURED_OUTPUT_SETTING_PATH


def _structured_policy() -> tuple[dict[str, object], int]:
    return {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {"fields": [{"path": ["note"], "role": "ordinary", "valueType": "string"}]},
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }


@dataclass
class _Args:
    harness: str
    json: bool = True


@dataclass
class _ManagedPolicy:
    settings: dict[str, object]
    content_hash: str


@dataclass
class _Config:
    managed_policy_status: str
    managed_policy_hash: str | None
    managed_locked_settings: tuple[str, ...]
    managed_policy: _ManagedPolicy | None


def _managed_config() -> _Config:
    policy_hash = "a" * 64
    return _Config(
        managed_policy_status="active",
        managed_policy_hash=policy_hash,
        managed_locked_settings=(STRUCTURED_OUTPUT_SETTING_PATH,),
        managed_policy=_ManagedPolicy(
            settings={"data_control": {"structured_output": _structured_policy()}},
            content_hash=policy_hash,
        ),
    )


def _optional_config() -> _Config:
    return _Config(
        managed_policy_status="absent",
        managed_policy_hash=None,
        managed_locked_settings=(),
        managed_policy=None,
    )


@dataclass
class _OverlayWorker(HookWorkerNativeMixin):
    config: _Config

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> _Config:
        return self.config


def _emit_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    config: _Config,
    recording_only: bool = False,
) -> tuple[dict[str, object], int]:
    emitted: dict[str, object] = {}

    def capture(command: str, payload: dict[str, object], as_json: bool) -> None:
        emitted.update(command=command, payload=payload, as_json=as_json)

    monkeypatch.setattr(availability, "_emit", capture)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    args = _Args(harness=harness)
    rc = availability._emit_native_unavailable(
        args,
        payload={"hook_event_name": event_name},
        workspace=context.workspace_dir,
        context=context,
        event_name=event_name,
        reason_code=reason_code,
        worker=_OverlayWorker(config),
        recording_only=recording_only,
    )
    assert emitted["command"] == "hook"
    assert emitted["as_json"] is True
    response = emitted["payload"]
    assert isinstance(response, dict)
    return response, rc


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(
    "reason_code",
    [
        "native_post_tool_unavailable",
        "native_review_deadline_exceeded",
        "native_command_control_fence_unavailable",
    ],
)
def test_cli_native_unavailable_withholds_managed_posttool_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
    reason_code: str,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        reason_code=reason_code,
        config=_managed_config(),
    )

    # PostToolUse unavailability is an allow envelope; rc mirrors verdict -> 0.
    assert rc == 0
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert response["reason_code"] == reason_code
    assert response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }
    assert "receipt" not in response
    assert "native_decision_id" not in response["structured_content_mediation"]


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_cli_native_unavailable_keeps_optional_structured_destination_off(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        config=_optional_config(),
    )

    assert rc == 0
    assert response == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "native_post_tool_unavailable",
    }


def _native_success_result() -> tuple[dict[str, object], int]:
    return {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reason": "native edge allowed",
        "reason_code": "native_allow",
        "reviewed_output_sha256": "a" * 64,
        "reviewed_excerpt": "native output",
    }


def _project_worker_result(
    worker_result: dict[str, object],
) -> tuple[dict[str, object], int]:
    response: dict[str, object] = {
        "decision": "allow",
        "policy_action": "allow",
        "existing_field": "preserved",
    }
    _apply_native_edge_envelope_fields(response, worker_result)
    return response


def test_cli_native_success_projects_worker_structured_mediation_without_mutating_native_fields(
    tmp_path: Path,
) -> None:
    native_result = _native_success_result()
    original_native_result = dict(native_result)
    structured_output = '{"note":"clean"}'
    worker_result = _OverlayWorker(_managed_config())._apply_structured_mediation(
        native_result,
        payload={"structured_output_json": structured_output},
        native_harness="pi",
        native_event="PostToolUse",
        accepted_receipt={"decision": "allow", "decision_id": "b" * 64},
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        deadline=None,
        recording_only=False,
    )

    response = _project_worker_result(worker_result)

    assert response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "forward",
        "reason_code": "structured_clean_forward",
        "native_decision_id": "b" * 64,
        "content_sha256": hashlib.sha256(structured_output.encode()).hexdigest(),
    }
    assert response["structured_content_mediation"] is not worker_result["structured_content_mediation"]
    assert native_result == original_native_result
    assert response["native_edge_decision"] == "allow"
    assert response["native_edge_reason"] == "native edge allowed"
    assert response["native_edge_reason_code"] == "native_allow"
    assert response["model_output_action"] == "allow_original"
    assert response["reviewed_output_sha256"] == "a" * 64
    assert response["reviewed_excerpt"] == "native output"
    assert response["existing_field"] == "preserved"


def test_cli_native_success_projects_managed_structured_withhold_and_keeps_optional_off(
    tmp_path: Path,
) -> None:
    native_result = _native_success_result()
    managed_worker_result = _OverlayWorker(_managed_config())._apply_structured_mediation(
        native_result,
        payload={"structured_output_json": '{"note": "not canonical"}'},
        native_harness="pi",
        native_event="PostToolUse",
        accepted_receipt={"decision": "allow", "decision_id": "c" * 64},
        guard_home=tmp_path / "managed-guard-home",
        workspace=tmp_path / "managed-workspace",
        deadline=None,
        recording_only=False,
    )
    optional_worker_result = _OverlayWorker(_optional_config())._apply_structured_mediation(
        native_result,
        payload={"structured_output_json": '{"note":"clean"}'},
        native_harness="pi",
        native_event="PostToolUse",
        accepted_receipt={"decision": "allow", "decision_id": "d" * 64},
        guard_home=tmp_path / "optional-guard-home",
        workspace=tmp_path / "optional-workspace",
        deadline=None,
        recording_only=False,
    )

    managed_response = _project_worker_result(managed_worker_result)
    optional_response = _project_worker_result(optional_worker_result)

    assert managed_response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_content_unproved",
        "native_decision_id": "c" * 64,
    }
    assert "structured_content_mediation" not in optional_response
    assert optional_worker_result == native_result


@pytest.mark.parametrize(
    ("recording_only", "decision", "reason_code"),
    [
        (False, "block", "native_prompt_unavailable"),
        (True, "allow", "native_prompt_deadline_exceeded"),
    ],
)
def test_cli_native_unavailable_preserves_native_recording_posture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    recording_only: bool,
    decision: str,
    reason_code: str,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness="pi",
        event_name="UserPromptSubmit",
        reason_code=reason_code,
        config=_optional_config(),
        recording_only=recording_only,
    )

    # pi/omp are envelope-driven: a preemptive (UserPromptSubmit) block rides
    # the decision envelope and exits 0 — nonzero rc reads as a hook error.
    # Gauntlet-verified: omp deny arrives as decision==deny while host exits 0.
    assert rc == 0
    assert response["decision"] == decision
    assert response["reason_code"] == reason_code
