from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.runtime import structured_output_mediation
from codex_plugin_scanner.guard.runtime.structured_output_mediation import (
    StructuredOutputBinding,
    mediate_native_post_tool_content,
    resolve_managed_structured_output_resolution,
)
from tests.structured_output_mediation_support import (
    _binding,
    _config,
    _LoadErrorNativeRouteFixture,
    _native_result,
    _NativeRouteFixture,
    _ObserveNativeRouteFixture,
    _policy_value,
    _real_observe_managed_config,
    _receipt,
    _UnavailableNativeRouteFixture,
)


def test_required_authority_failure_withholds_after_native_receipt() -> None:
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=None,
        binding=None,
        required_reason_code="structured_managed_authority_unavailable",
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.reason_code == "structured_managed_authority_unavailable"


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered"])
def test_load_config_fail_closed_floor_keeps_structured_authority_required(
    tmp_path: Path,
    status: str,
) -> None:
    config = load_guard_config(
        tmp_path / "guard-home",
        managed_policy_state=ManagedPolicyState(status, "machine-policy-fixture"),
    )
    assert config.managed_policy_status == status
    assert config.mode == "enforce"
    assert config.default_action == "block"
    assert config.managed_policy is not None
    resolution = resolve_managed_structured_output_resolution(config, harness="pi")
    assert resolution.required is True
    assert resolution.reason_code == "structured_managed_authority_unavailable"


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_clean_forward_requires_complete_recheck_and_exposes_only_ephemeral_digest(harness: str) -> None:
    candidate = '{"employee":{"email":"","id":7},"note":"π"}'
    binding = _binding(harness)
    refreshed: list[StructuredOutputBinding | None] = [binding]
    result = mediate_native_post_tool_content(
        harness=harness,
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=candidate,
        binding=binding,
        recheck_binding=lambda: refreshed[0],
    )

    assert result is not None
    assert result.action == "forward"
    assert result.reason_code == "structured_clean_forward"
    assert result.native_decision_id == "b" * 64
    assert result.content_sha256 == hashlib.sha256(candidate.encode()).hexdigest()
    assert "email" not in str(result.to_harness_json())
    assert "π" not in str(result.to_harness_json())

    refreshed[0] = None
    changed = mediate_native_post_tool_content(
        harness=harness,
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=candidate,
        binding=binding,
        recheck_binding=lambda: refreshed[0],
    )
    assert changed is not None
    assert changed.action == "withhold"
    assert changed.reason_code == "structured_binding_changed"
    assert changed.content_sha256 is None


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_forged_tool_authentication_roles_cannot_relax_model_visible_mediation(harness: str) -> None:
    forged_destination = _policy_value()
    forged_destination["destinationRole"] = "tool_authentication"
    with pytest.raises(ValueError, match="destination role is unsupported"):
        structured_output_mediation.parse_structured_output_policy(forged_destination)

    forged_field_role = _policy_value()
    forged_field = dict(forged_field_role["schema"]["fields"][0])
    forged_field["role"] = "tool_authentication"
    forged_field_role["schema"] = {"fields": [forged_field]}
    with pytest.raises(ValueError, match="field 0 role is invalid"):
        structured_output_mediation.parse_structured_output_policy(forged_field_role)

    forged_payload_label = '{"destinationRole":"tool_authentication","employee":{"email":"","id":7},"note":"x"}'
    result = mediate_native_post_tool_content(
        harness=harness,
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=forged_payload_label,
        binding=_binding(harness),
        recheck_binding=lambda: _binding(harness),
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.reason_code == "structured_unknown_field"
    assert result.content_sha256 is None


@pytest.mark.parametrize("error_type", [ValueError, OSError])
def test_binding_recheck_failure_withholds_without_logging_callback_details(
    error_type: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fail_recheck() -> StructuredOutputBinding | None:
        raise error_type("untrusted callback detail")

    native_result = _native_result()
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding(),
        recheck_binding=fail_recheck,
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.content_sha256 is None
    assert native_result == _native_result()
    assert "untrusted callback detail" not in caplog.text
    assert "untrusted callback detail" not in str(result.to_harness_json())
    if error_type is OSError:
        assert result.reason_code == "structured_binding_recheck_failed"
        assert "OSError" in caplog.text
    else:
        assert result.reason_code == "structured_binding_changed"
        assert not caplog.records


def test_match_unsupported_deadline_missing_receipt_and_native_deny_withhold() -> None:
    binding = _binding("omp")
    cases = (
        ("{'employee': {'email': 'person@example.test', 'id': 7}, 'note': 'x'}", "structured_content_unproved"),
        ('{"employee":{"email":"person@example.test","id":7},"note":"x"}', "structured_declared_schema_scan"),
        ('{"employee":{"email":"","id":7},"note":"x"}', "structured_receipt_missing"),
    )
    for candidate, expected_reason in cases:
        result = mediate_native_post_tool_content(
            harness="omp",
            event_name="PostToolUse",
            native_result=_native_result(),
            validated_receipt=None if expected_reason == "structured_receipt_missing" else _receipt(),
            structured_output_json=candidate,
            binding=binding,
            recheck_binding=lambda: binding,
        )
        assert result is not None
        assert result.action == "withhold"
        assert result.reason_code == expected_reason
        assert result.content_sha256 is None

    denied = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(decision="deny", model_output_action="block"),
        validated_receipt=_receipt(decision="deny"),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=binding,
        recheck_binding=lambda: binding,
    )
    assert denied is None

    expired = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding("pi"),
        recheck_binding=lambda: _binding("pi"),
        deadline_monotonic=-1,
    )
    assert expired is not None
    assert expired.reason_code == "structured_review_deadline_exceeded"


def test_native_route_attaches_adapter_field_after_receipt_without_mutating_native_result(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config())
    native = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    response, native_used = native
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "forward"
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_native_unavailable_required_structured_route_withholds_model_output(
    tmp_path: Path,
    harness: str,
) -> None:
    class _Metrics:
        def record_route(self, _route: str) -> None:
            return None

    fixture = _UnavailableNativeRouteFixture(_config())
    fixture.metrics = _Metrics()
    fixture.activity_writer = None
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={"hook_event_name": "PostToolUse"},
        harness=harness,
        event_name="PostToolUse",
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )

    assert native_used is False
    assert response["decision"] == "allow"
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }


def test_native_route_load_error_attaches_fail_closed_mediation(tmp_path: Path) -> None:
    fixture = _LoadErrorNativeRouteFixture(_config())
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] == "structured_managed_authority_unavailable"


@pytest.mark.parametrize(
    ("candidate", "expected_action"),
    (
        ('{"employee":{"email":"","id":7},"note":"x"}', "forward"),
        ('{"employee":{"email":"person@example.test","id":7},"note":"x"}', "withhold"),
    ),
)
def test_recording_only_cannot_bypass_real_managed_structured_policy(
    tmp_path: Path,
    candidate: str,
    expected_action: str,
) -> None:
    config = _real_observe_managed_config(tmp_path)
    fixture = _ObserveNativeRouteFixture(config)
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": candidate,
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "observe"},
        recording_only=True,
    )
    assert native_used is True
    assert response["observe_mode"] is True
    assert fixture.raw_result == _native_result(observe_mode=True)
    assert fixture.raw_receipt == _receipt()
    assert fixture.recorded_receipt == _receipt()
    assert response["decision"] == fixture.raw_result["decision"]
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == expected_action


def test_recording_only_unconfigured_route_keeps_existing_watch_behavior(tmp_path: Path) -> None:
    fixture = _ObserveNativeRouteFixture(_config(status="absent", locked=()))
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"person@example.test","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "observe"},
        recording_only=True,
    )
    assert native_used is True
    assert response["observe_mode"] is True
    assert "structured_content_mediation" not in response


@pytest.mark.parametrize(
    ("harness", "event_name", "native_overrides", "binding", "required_reason"),
    [
        ("codex", "PostToolUse", {}, _binding("pi"), None),
        ("pi", "PreToolUse", {}, _binding("pi"), None),
        ("pi", "PostToolUse", {"observe_mode": True}, _binding("pi"), None),
        ("pi", "PostToolUse", {}, None, None),
        ("omp", "PostToolUse", {}, _binding("pi"), None),
    ],
)
def test_mediation_early_exits_preserve_native_authority(
    harness: str,
    event_name: str,
    native_overrides: dict[str, object],
    binding: StructuredOutputBinding | None,
    required_reason: str | None,
) -> None:
    native_result = _native_result(**native_overrides)
    original_result = dict(native_result)
    result = mediate_native_post_tool_content(
        harness=harness,
        event_name=event_name,
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=binding,
        required_reason_code=required_reason,
    )
    assert result is None
    assert native_result == original_result


@pytest.mark.parametrize(
    ("native_overrides", "expected_reason", "cancelled", "recheck"),
    [
        ({"model_output_action": "review"}, "structured_content_unproved", False, "present"),
        ({}, "structured_review_cancelled", True, "present"),
        ({}, "structured_binding_recheck_missing", False, "missing"),
    ],
)
def test_mediation_withholds_unproved_or_cancelled_content_without_native_rewrite(
    native_overrides: dict[str, object],
    expected_reason: str,
    cancelled: bool,
    recheck: str,
) -> None:
    native_result = _native_result(**native_overrides)
    original_result = dict(native_result)
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding(),
        cancelled=cancelled,
        recheck_binding=(lambda: _binding()) if recheck == "present" else None,
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.reason_code == expected_reason
    assert result.content_sha256 is None
    assert native_result == original_result
