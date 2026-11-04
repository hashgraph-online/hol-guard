"""Yanez Pulse glue: the CLI and dashboard reach the same resident call for the same action.

The resident is stubbed at the ``approval_gate._approval_gate_native`` seam. The
receipt checks themselves are covered by the Rust acceptance tests in
``rust/crates/guard-runtime/src/approval_gate_pulse_tests.rs`` and
``rust/crates/guard-yanez-pulse/src/receipt_tests.rs``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approval_gate, approval_gate_pulse
from codex_plugin_scanner.guard.approval_gate_types import (
    ApprovalGateError,
    ApprovalGateInput,
    config_from_wire,
    input_from_mapping,
    settings_input_from_payload,
)
from codex_plugin_scanner.guard.native_approval_gate import _input_to_wire

_GRANT = {
    "grant_id": "g1",
    "purpose": "approval_decision",
    "issued_at": "2026-10-02T00:00:00+00:00",
    "expires_at": "2026-10-02T00:05:00+00:00",
    "action": "allow",
    "scope": "workspace",
    "subject": "",
    "session_nonce": "",
    "factor_set": ["pulse"],
    "strict": False,
    "used_cooldown": False,
    "cooldown_expires_at": None,
    "password_verified": False,
    "totp_verified": False,
}


class FakeResident:
    """A gate that uses Pulse. ``polls`` is what the YID app reports, in order."""

    def __init__(self, polls: list[str | ApprovalGateError], *, cooldown_covered: bool = False) -> None:
        self.polls = list(polls)
        self.cooldown_covered = cooldown_covered
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, method: str, guard_home: Path, **kwargs: object) -> dict[str, object]:
        self.calls.append((method, kwargs))
        gate_input = kwargs.get("approval_gate_input")
        if method == "pulse_request":
            if self.cooldown_covered:
                return {"status": "cooldown_covered"}
            return {"status": "pending", "request_id": "azr_1", "match_code": "ABC123", "decide_by": "x"}
        if method == "pulse_poll":
            answer = self.polls.pop(0) if self.polls else "expired"
            if isinstance(answer, ApprovalGateError):
                raise answer
            return {"status": answer}
        if method == "require_approval_decision":
            pulse_id = getattr(gate_input, "pulse_request_id", None)
            if pulse_id == "azr_1" or (self.cooldown_covered and len(self.calls) > 2):
                return {"grant": dict(_GRANT)}
            raise ApprovalGateError("approval_gate_pulse_required", "Approve this action in the YID app.")
        raise AssertionError(f"unexpected method {method}")

    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]


@pytest.fixture
def resident(monkeypatch: pytest.MonkeyPatch):
    def install(fake: FakeResident) -> FakeResident:
        monkeypatch.setattr(approval_gate, "_approval_gate_native", fake)
        monkeypatch.setattr(approval_gate_pulse, "_PULSE_POLL_INTERVAL_SECONDS", 0.0)
        return fake

    return install


def _decide(tmp_path: Path, gate_input: ApprovalGateInput | None):
    return approval_gate.require_approval_decision(
        tmp_path, action="allow", scope="workspace", approval_gate_input=gate_input
    )


def test_cli_waits_for_the_yid_app_then_retries_the_same_action(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident(["pending", "pending", "approved"]))
    seen: list[str] = []
    grant = _decide(tmp_path, ApprovalGateInput(pulse_mode="wait", pulse_on_status=lambda s, _: seen.append(s)))
    assert grant is not None and grant.factor_set == ("pulse",)
    assert fake.methods() == [
        "require_approval_decision",
        "pulse_request",
        "pulse_poll",
        "pulse_poll",
        "pulse_poll",
        "require_approval_decision",
    ]
    first, retry = fake.calls[0][1], fake.calls[-1][1]
    assert first["params"] == retry["params"], "the retry asks for exactly the action the user approved"
    request = fake.calls[1][1]
    assert request["purpose"] == "approval_decision"
    assert request["params"]["action"] == "allow" and request["params"]["scope"] == "workspace"
    assert seen == ["pending", "approved"]


def _unreachable() -> ApprovalGateError:
    return ApprovalGateError("approval_gate_pulse_unavailable", "Yanez Pulse is unreachable.", status=503)


def test_a_bulk_approval_names_its_requests_to_the_resident(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident(["approved"]))
    _decide(tmp_path, ApprovalGateInput(pulse_mode="wait", pulse_batch_request_ids=("r2", "r1")))
    request = next(kw for method, kw in fake.calls if method == "pulse_request")
    assert request["params"]["batch_request_ids"] == ["r2", "r1"]
    single = resident(FakeResident(["approved"]))
    _decide(tmp_path, ApprovalGateInput(pulse_mode="wait"))
    assert "batch_request_ids" not in next(kw for m, kw in single.calls if m == "pulse_request")["params"]


def test_a_check_that_cannot_reach_pulse_is_tried_again(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident(["pending", _unreachable(), "approved"]))
    grant = _decide(tmp_path, ApprovalGateInput(pulse_mode="wait"))
    assert grant is not None and fake.methods().count("pulse_poll") == 3


def test_pulse_still_unreachable_at_the_deadline_fails_closed(
    resident, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = resident(FakeResident([_unreachable()] * 1000))
    monkeypatch.setattr(approval_gate_pulse, "_PULSE_POLL_INTERVAL_SECONDS", 0.01)
    request = {"request_id": "azr_1"}
    with pytest.raises(ApprovalGateError) as raised:
        approval_gate_pulse.await_pulse_approval(tmp_path, request, deadline_seconds=0.05)
    assert raised.value.code == "approval_gate_pulse_unavailable"
    assert fake.methods().count("pulse_poll") >= 1


@pytest.mark.parametrize(
    ("status", "code"), [("rejected", "approval_gate_pulse_rejected"), ("expired", "approval_gate_pulse_expired")]
)
def test_rejection_and_expiry_fail_closed(tmp_path: Path, resident, status: str, code: str) -> None:
    fake = resident(FakeResident([status]))
    with pytest.raises(ApprovalGateError) as raised:
        _decide(tmp_path, ApprovalGateInput(pulse_mode="wait"))
    assert raised.value.code == code
    assert fake.methods().count("require_approval_decision") == 1


def test_dashboard_defer_mode_hands_back_the_request_to_poll(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident([]))
    gate_input = input_from_mapping({"approval_gate_pulse": True})
    with pytest.raises(ApprovalGateError) as raised:
        _decide(tmp_path, gate_input)
    payload = raised.value.to_payload()
    assert raised.value.status == 202
    assert payload["error"] == "approval_gate_pulse_pending"
    assert payload["pulse_request_id"] == "azr_1" and payload["pulse_match_code"] == "ABC123"
    assert "pulse_poll" not in fake.methods(), "the daemon never blocks a request on the YID app"
    # The dashboard resubmits with the id; the same resident call grants it.
    grant = _decide(tmp_path, input_from_mapping({"approval_pulse_request_id": "azr_1"}))
    assert grant is not None and grant.factor_set == ("pulse",)


def test_cli_and_dashboard_send_the_same_pulse_request(tmp_path: Path, resident) -> None:
    cli = resident(FakeResident(["approved"]))
    _decide(tmp_path, ApprovalGateInput(pulse_mode="wait"))
    dashboard = resident(FakeResident([]))
    with pytest.raises(ApprovalGateError):
        _decide(tmp_path, input_from_mapping({"approval_gate_pulse": True}))
    cli_request = next(kw for method, kw in cli.calls if method == "pulse_request")
    dashboard_request = next(kw for method, kw in dashboard.calls if method == "pulse_request")
    assert cli_request == dashboard_request


def test_without_opt_in_no_pulse_request_is_created(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident(["approved"]))
    with pytest.raises(ApprovalGateError) as raised:
        _decide(tmp_path, ApprovalGateInput(password="correct horse battery"))
    assert raised.value.code == "approval_gate_pulse_required"
    assert fake.methods() == ["require_approval_decision"]


def test_an_open_cooldown_sends_no_pulse_notification(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident([], cooldown_covered=True))
    grant = _decide(tmp_path, ApprovalGateInput(pulse_mode="wait"))
    assert grant is not None
    assert "pulse_poll" not in fake.methods()
    assert fake.calls[-1][1]["approval_gate_input"].pulse_request_id is None


def test_fixed_scope_mutations_name_the_scope_the_resident_binds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResident(["approved"])

    def native(method: str, guard_home: Path, **kwargs: object) -> dict[str, object]:
        if (
            method == "require_extension_control"
            and getattr(kwargs.get("approval_gate_input"), "pulse_request_id", None) is None
        ):
            fake.calls.append((method, kwargs))
            raise ApprovalGateError("approval_gate_pulse_required", "Approve in the YID app.")
        if method == "require_extension_control":
            return {"grant": {**_GRANT, "purpose": "extension_control_mutation"}}
        return fake(method, guard_home, **kwargs)

    monkeypatch.setattr(approval_gate, "_approval_gate_native", native)
    monkeypatch.setattr(approval_gate_pulse, "_PULSE_POLL_INTERVAL_SECONDS", 0.0)
    approval_gate.require_extension_control(
        tmp_path,
        approval_gate_input=ApprovalGateInput(pulse_mode="wait"),
        action="enable",
        subject="s",
        session_nonce="n",
    )
    request = next(kw for method, kw in fake.calls if method == "pulse_request")
    assert request["purpose"] == "extension_control_mutation"
    assert request["params"]["scope"] == "extension-control-authority"
    assert request["strict"] is True


def test_secrets_reach_the_wire_but_never_a_repr() -> None:
    gate_input = ApprovalGateInput(
        pulse_agent_key="yak_secret_value", pulse_recovery_code="code-123", pulse_request_id="azr_1"
    )
    wire = _input_to_wire(gate_input)
    assert wire is not None
    assert wire["pulse_agent_key"] == "yak_secret_value"
    assert wire["pulse_recovery_code"] == "code-123"
    assert wire["pulse_request_id"] == "azr_1"
    assert "yak_secret_value" not in repr(gate_input) and "code-123" not in repr(gate_input)
    assert "pulse_mode" not in wire, "the mode is a local choice, not resident input"


def test_public_config_reads_pulse_fields() -> None:
    config = config_from_wire(
        {
            "enabled": True,
            "configured": True,
            "cooldown_seconds": 0,
            "cooldown_active": False,
            "fail_closed": False,
            "strict_all_decisions": False,
            "totp_enabled": False,
            "totp_pending": False,
            "pulse_enabled": True,
            "pulse_cooldown_seconds": 900,
        }
    )
    assert config is not None and config.pulse_enabled
    assert config.to_dict()["pulse_cooldown_seconds"] == 900
    older = config_from_wire({k: v for k, v in config.to_dict().items() if not k.startswith("pulse_")})
    assert older is not None and older.pulse_enabled is False


def test_a_settings_save_retry_asks_for_a_pulse_request(tmp_path: Path, resident) -> None:
    # The dashboard retries a refused settings save with a top-level Pulse field,
    # while the rest of the payload keeps its usual ``settings`` shape.
    fake = resident(FakeResident([]))
    payload = {"settings": {"approval_gate": {"enabled": True}}, "approval_gate_pulse": True}
    gate_input = settings_input_from_payload(payload)
    assert gate_input is not None and gate_input.pulse_mode == "defer"
    with pytest.raises(ApprovalGateError) as raised:
        _decide(tmp_path, gate_input)
    assert raised.value.status == 202 and raised.value.code == "approval_gate_pulse_pending"
    assert "pulse_request" in fake.methods()


def test_a_settings_save_resubmit_sends_the_request_id_without_a_password() -> None:
    payload = {
        "settings": {"approval_gate": {"enabled": True, "password": "correct horse battery"}},
        "approval_pulse_request_id": "azr_1",
    }
    gate_input = settings_input_from_payload(payload)
    assert gate_input is not None and gate_input.pulse_request_id == "azr_1"
    assert gate_input.pulse_mode == "off" and gate_input.password is None


def test_a_settings_save_without_pulse_fields_is_unchanged() -> None:
    nested = {"settings": {"approval_gate": {"password": "correct horse battery"}}}
    assert settings_input_from_payload(nested) == input_from_mapping(
        {"approval_gate": nested["settings"]["approval_gate"]}
    )
    top_level = {"settings": {"mode": "enforce"}, "approval_password": "correct horse battery"}
    assert settings_input_from_payload(top_level) == input_from_mapping(top_level)
    assert settings_input_from_payload({"settings": {"mode": "enforce"}}) is None
