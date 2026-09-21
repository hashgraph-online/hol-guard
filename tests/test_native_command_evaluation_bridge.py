"""Native diagnostic orchestration must not fall back to Python matching."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import command_inspection
from codex_plugin_scanner.guard.runtime import native_command_evaluation as bridge
from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import NativeCommandExtensionEvidenceError


def test_missing_snapshot_does_not_query_or_evaluate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bridge, "current_extension_control_snapshot", lambda: None)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("unbound diagnostics queried or evaluated a command")

    monkeypatch.setattr(bridge, "review_pre_tool_native", forbidden)
    monkeypatch.setattr(bridge, "evaluate_command", forbidden)
    assert bridge.evaluate_command_native("git status", guard_home=tmp_path) is None


@pytest.fixture
def bound_transport(monkeypatch: pytest.MonkeyPatch) -> tuple:
    snapshot = SimpleNamespace(authority_failure=None)
    canonical = object()
    payload = {"command_model": {"normalized_text": "fixture destroy"}, "minimum_action": "review"}
    monkeypatch.setattr(bridge, "review_pre_tool_native", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(bridge, "_canonical_command_from_native", lambda *_args: canonical)
    return snapshot, canonical, payload


def test_projection_receives_exact_native_response_and_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bound_transport: tuple,
) -> None:
    snapshot, canonical, payload = bound_transport
    result = SimpleNamespace(minimum_action="review")

    def project(command: str, **kwargs: object) -> object:
        assert command == "fixture destroy"
        assert kwargs["native_extension_evidence"] is payload
        assert kwargs["extension_control_snapshot"] is snapshot
        assert kwargs["canonical_command"] is canonical
        return result

    monkeypatch.setattr(bridge, "evaluate_command", project)
    reviewed = bridge.review_command_native("fixture destroy", guard_home=tmp_path, extension_control_snapshot=snapshot)
    assert reviewed is not None
    assert reviewed.evaluation is result
    assert reviewed.payload is payload and reviewed.snapshot is snapshot


def test_projection_cannot_weaken_native_hard_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bound_transport: tuple,
) -> None:
    snapshot, _, payload = bound_transport
    payload["minimum_action"] = "block"
    monkeypatch.setattr(bridge, "evaluate_command", lambda *_args, **_kwargs: SimpleNamespace(minimum_action="allow"))
    assert (
        bridge.evaluate_command_native("fixture destroy", guard_home=tmp_path, extension_control_snapshot=snapshot)
        is None
    )


def test_invalid_native_binding_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bound_transport: tuple,
) -> None:
    snapshot, _, _ = bound_transport

    def reject(*_args: object, **_kwargs: object) -> None:
        raise NativeCommandExtensionEvidenceError("stale native controls")

    monkeypatch.setattr(bridge, "evaluate_command", reject)
    assert (
        bridge.evaluate_command_native("fixture destroy", guard_home=tmp_path, extension_control_snapshot=snapshot)
        is None
    )


def test_inspection_unavailable_is_not_benign(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(command_inspection, "review_command_native", lambda *_args, **_kwargs: None)
    result = command_inspection.inspect_command("git status", cwd=tmp_path, home_dir=tmp_path, guard_home=tmp_path)
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "review"
    assert result["classification"]["explicitly_benign"] is False
    assert result["rules"] == []


def test_inspection_native_evaluation_failure_preserves_block_without_reparsing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tests.native_command_test_support import real_native_command_evaluation

    command = "sudo -u alternate-user git push origin main --force"
    reviewed = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path)
    original = deepcopy(reviewed.payload)
    assert reviewed.payload["command_extensions"]["evaluation_error"] == "native_command_evaluation_failed"
    assert reviewed.evaluation.minimum_action == "block"
    monkeypatch.setattr(command_inspection, "review_command_native", lambda *_args, **_kwargs: reviewed)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("failed native inspection reparsed or classified the command")

    monkeypatch.setattr(command_inspection, "parse_shell_command", forbidden)
    monkeypatch.setattr(command_inspection, "extract_sensitive_tool_action_request", forbidden)
    monkeypatch.setattr(command_inspection, "build_tool_action_request_artifact", forbidden)
    result = command_inspection.inspect_command(command, cwd=tmp_path, home_dir=tmp_path, guard_home=tmp_path)

    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"
    assert result["classification"]["matched"] is False
    assert result["classification"]["explicitly_benign"] is False
    assert result["classification"]["action_class"] is None
    assert "failed" in result["classification"]["reason"]
    assert result["command_model"] == reviewed.evaluation.command.to_dict()
    assert result["command_model"]["uncertainty_reason"] == "transparent_wrapper_not_yet_supported"
    assert result["controlling_rule_id"] is None
    assert result["rules"] == result["extensions"] == result["signals"] == []
    assert result["trace"] == [
        {
            "step": "native-command-evidence",
            "result": "failed",
            "detail": "Native command evaluation failed; the bound native model and terminal block are preserved.",
        }
    ]
    assert reviewed.payload == original
