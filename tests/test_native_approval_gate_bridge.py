"""The approval-gate bridge fails closed for a provisioned resident only."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_approval_gate as bridge
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256


def _provision(monkeypatch: pytest.MonkeyPatch, answer, *, failure_code: str | None = None) -> None:
    status = SimpleNamespace(
        mode="force",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="sha"),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "approval-gate-v2")),
    )
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: status)

    def respond(**kwargs: object) -> bytes | None:
        # A callable answer is built from the request, as the resident binds it.
        return answer(json.loads(kwargs["payload"])["request"]) if callable(answer) else answer

    monkeypatch.setattr(bridge, "native_resident_client_request", respond)
    monkeypatch.setattr(bridge, "native_resident_client_failure_code", lambda: failure_code)
    for name in ("native_record_resident_failure", "native_record_resident_success", "native_record_overload"):
        monkeypatch.setattr(bridge, name, lambda *_args, **_kwargs: None)


def _ok(payload: object):
    def bound(request: dict[str, object]) -> bytes:
        return json.dumps(
            {
                "schema": "guard-approval-gate-result.v1",
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "ok",
                "payload": payload,
            },
        ).encode()

    return bound


def test_well_formed_payload_is_returned(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _provision(monkeypatch, _ok({"grant": None}))
    assert bridge.approval_gate_native("require_approval_decision", tmp_path) == {"grant": None}


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("require_approval_decision", {}),
        ("require_high_risk", {"grant": "not-a-grant"}),
        ("public_config", {}),
        ("update_settings", {"enabled": True}),
        ("recent_totp_satisfied", {}),
        ("begin_totp_enrollment", {}),
    ],
)
def test_malformed_ok_payload_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, method: str, payload: object
) -> None:
    _provision(monkeypatch, _ok(payload))
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native(method, tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"


@pytest.mark.parametrize(
    "error",
    ["native_policy_verifier_key_missing", "native_resident_state_dir_create_failed"],
)
def test_unprovisioned_home_is_not_a_native_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: str
) -> None:
    _provision(monkeypatch, json.dumps({"error": error, "retryable": False}).encode())
    assert bridge.approval_gate_native("public_config", tmp_path) is None


def test_unprovisioned_spawn_failure_is_not_a_native_authority(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _provision(monkeypatch, None, failure_code="native_policy_verifier_key_missing")
    assert bridge.approval_gate_native("public_config", tmp_path) is None


@pytest.mark.parametrize(
    "answer",
    [None, b"not json", json.dumps({"error": "native_runtime_panicked", "retryable": False}).encode()],
)
def test_provisioned_resident_that_does_not_answer_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: bytes | None
) -> None:
    _provision(monkeypatch, answer, failure_code="native_client_timed_out")
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native("public_config", tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"


def test_envelope_bound_to_another_request_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _provision(
        monkeypatch,
        lambda request: json.dumps(
            {
                "schema": "guard-approval-gate-result.v1",
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + "0" * 64,
                "status": "ok",
                "payload": {"grant": None},
            }
        ).encode(),
    )
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native("require_approval_decision", tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"


@pytest.mark.parametrize(("provision", "expected_calls"), [(False, 0), (True, 1)])
def test_only_configuration_calls_establish_the_resident_verifier_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, provision: bool, expected_calls: int
) -> None:
    _provision(monkeypatch, _ok({"grant": None}))
    provisioned: list[Path] = []

    def establish(guard_home: Path) -> bool:
        provisioned.append(guard_home)
        return True

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", establish)
    bridge.approval_gate_native("require_approval_decision", tmp_path, provision_prerequisite=provision)
    assert len(provisioned) == expected_calls


def test_runtime_without_the_current_approval_gate_capability_is_not_asked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _provision(monkeypatch, _ok({"grant": None}))
    stale = SimpleNamespace(
        mode="force",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="sha"),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "approval-gate-v1")),
    )
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: stale)
    assert bridge.approval_gate_native("require_approval_decision", tmp_path) is None
