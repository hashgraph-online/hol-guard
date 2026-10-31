"""The approval-gate bridge fails closed for a provisioned resident only."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_approval_gate as bridge
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.native_approval_errors import resident_refusal_code
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256


def _provision(monkeypatch: pytest.MonkeyPatch, answer, *, failure_code: str | None = None) -> None:
    status = SimpleNamespace(
        mode="force",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="sha"),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "approval-gate-v2")),
    )
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: status)

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


@pytest.mark.parametrize(
    "error",
    [
        "native_resident_windows_private_ancestry_missing",
        "native_resident_windows_access_denied",
        "native_resident_windows_acl_not_private",
    ],
)
def test_platform_specific_state_failures_stay_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: str
) -> None:
    # The resident folds a missing state directory into the shared unprovisioned
    # code; any other Windows state failure is a real fault, not "no authority".
    _provision(monkeypatch, json.dumps({"error": error, "retryable": False}).encode())
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native("public_config", tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"


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


class _HostileDiagnosticCode:
    def __str__(self):
        raise AssertionError("PRIVATE_PAYLOAD")

    def __hash__(self):
        raise AssertionError("PRIVATE_PAYLOAD")


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "code",
    ["native_client_connect_failed", "native_client_timed_out", "PRIVATE_PAYLOAD", None, _HostileDiagnosticCode()],
)
def test_transport_diagnostic_is_opt_in_and_uses_finite_codes(monkeypatch, tmp_path, capsys, enabled, code):
    _provision(monkeypatch, None)
    monkeypatch.setattr(bridge, "native_resident_client_failure_code", lambda: code)
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1" if enabled else "0")
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native("public_config", tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"
    assert caught.value.status == 503
    assert str(caught.value) == "The native approval authority did not answer. Retry the approval."
    expected = (
        code if type(code) is str and code in {"native_client_connect_failed", "native_client_timed_out"} else "unknown"
    )
    assert capsys.readouterr().err == (
        f"native_approval_gate_transport_unavailable stage=request code={expected}\n" if enabled else ""
    )


def test_python_diagnostic_code_does_not_expand_native_refusal_vocabulary():
    assert resident_refusal_code({"error": "native_client_timed_out", "retryable": False}) is None


@pytest.mark.parametrize(
    "target", ["native_resident_client_failure_code", "non_production_diagnostic_enabled", "print"]
)
def test_transport_diagnostic_errors_preserve_original_failure(monkeypatch, tmp_path, capsys, target):
    _provision(monkeypatch, None, failure_code="native_client_connect_failed")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")

    def broken(*_args, **_kwargs):
        raise RuntimeError("PRIVATE_EXCEPTION")

    monkeypatch.setattr(bridge, target, broken, raising=False)
    with pytest.raises(ApprovalGateError) as caught:
        bridge.approval_gate_native("public_config", tmp_path)
    assert caught.value.code == "native_approval_gate_unavailable"
    assert caught.value.status == 503
    assert str(caught.value) == "The native approval authority did not answer. Retry the approval."
    assert capsys.readouterr().err == (
        "native_approval_gate_transport_unavailable stage=request code=unknown\n"
        if target == "native_resident_client_failure_code"
        else ""
    )


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
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: stale)
    assert bridge.approval_gate_native("require_approval_decision", tmp_path) is None


@pytest.mark.parametrize(("warm", "minimum", "maximum"), [(True, 3.0, 5.5), (False, 13.0, 15.5)])
def test_cold_resident_gets_a_spawn_allowance_and_a_warm_one_keeps_the_tight_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    warm: bool,
    minimum: float,
    maximum: float,
) -> None:
    budgets: list[float] = []
    _provision(monkeypatch, _ok({"grant": None}))
    answer = _ok({"grant": None})

    def respond(**kwargs: object) -> bytes | None:
        budgets.append(float(kwargs["deadline_monotonic"]) - bridge.time.monotonic())  # type: ignore[arg-type]
        return answer(json.loads(kwargs["payload"])["request"])  # type: ignore[arg-type]

    monkeypatch.setattr(bridge, "native_resident_client_request", respond)
    monkeypatch.setattr(bridge, "native_resident_client_ready", lambda *_args, **_kwargs: warm)

    assert bridge.approval_gate_native("require_approval_decision", tmp_path) == {"grant": None}
    assert minimum <= budgets[0] <= maximum
