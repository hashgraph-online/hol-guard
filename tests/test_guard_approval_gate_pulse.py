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


class _EnrollmentResident:
    def __init__(self) -> None:
        self.params: list[dict[str, object]] = []

    def __call__(self, method: str, guard_home: Path, **kwargs: object) -> dict[str, object]:
        assert method == "begin_pulse_enrollment"
        self.params.append(dict(kwargs.get("params") or {}))
        return {"status": "pending", "request_id": "azr_1", "match_code": "ABC123"}


def test_enrollment_sends_the_chosen_floor_and_leaves_the_default_to_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _EnrollmentResident()
    monkeypatch.setattr(approval_gate, "_approval_gate_native", fake)
    gate_input = ApprovalGateInput(password="pw", pulse_agent_key="yak_x")
    approval_gate_pulse.begin_pulse_enrollment(tmp_path, approval_gate_input=gate_input, min_tier="high")
    approval_gate_pulse.begin_pulse_enrollment(tmp_path, approval_gate_input=gate_input)
    assert fake.params[0]["min_tier"] == "high"
    assert "min_tier" not in fake.params[1], "the resident's default is medium"


def test_the_cli_offers_only_medium_and_high() -> None:
    import argparse

    from codex_plugin_scanner.guard.cli.approval_pulse_commands import add_approval_pulse_parser

    root = argparse.ArgumentParser()
    settings = root.add_subparsers(dest="settings_command")
    add_approval_pulse_parser(settings, lambda parser, **_: None, argparse.ArgumentParser)
    assert root.parse_args(["approval-pulse", "enroll"]).min_tier == "medium"
    assert root.parse_args(["approval-pulse", "enroll", "--min-tier", "high"]).min_tier == "high"
    with pytest.raises(SystemExit):
        root.parse_args(["approval-pulse", "enroll", "--min-tier", "low"])


@pytest.mark.parametrize("floor", ["low", "ultra", 2])
def test_the_resident_refuses_a_floor_below_medium_or_unknown(tmp_path: Path, floor: object) -> None:
    # The real resident: the floor is checked before setup contacts Yanez.
    with pytest.raises(ApprovalGateError) as refused:
        approval_gate_pulse.begin_pulse_enrollment(
            tmp_path,
            approval_gate_input=ApprovalGateInput(password="pw", pulse_agent_key="yak_x"),
            min_tier=floor,
        )
    assert refused.value.code == "approval_gate_pulse_invalid_tier"


# Review of #7352.


def test_a_daemon_bound_cli_command_waits_for_the_yid_app_and_sends_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import submit_with_pulse

    monkeypatch.setattr(approval_gate_pulse, "_PULSE_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(approval_gate, "_approval_gate_native", FakeResident(["pending", "approved"]))
    sent: list[dict[str, object]] = []

    def daemon(payload: dict[str, object]) -> dict[str, object]:
        sent.append(payload)
        if payload.get("approval_pulse_request_id") == "azr_1":
            return {"proof_id": "p1"}
        assert payload.get("approval_gate_pulse") is True
        return {"error": "approval_gate_pulse_pending", "pulse_request_id": "azr_1", "pulse_match_code": "ABC123"}

    original = {"session_nonce": "n", "layers": []}
    result = submit_with_pulse(tmp_path, daemon, original, ApprovalGateInput(pulse_mode="wait"))
    assert result == {"proof_id": "p1"}
    assert len(sent) == 2
    assert "approval_pulse_request_id" not in sent[0] and "approval_gate_pulse" not in sent[1]
    assert original == {"session_nonce": "n", "layers": []}, "the caller's payload is not changed"


def test_without_pulse_a_daemon_bound_cli_command_is_sent_once(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import submit_with_pulse

    sent: list[dict[str, object]] = []
    submit_with_pulse(tmp_path, lambda p: sent.append(p) or {}, {"approval_password": "pw"}, ApprovalGateInput())
    assert sent == [{"approval_password": "pw"}]


def test_extension_routes_hand_back_the_pulse_request_to_approve() -> None:
    from codex_plugin_scanner.guard.daemon.extension_control_errors import approval_gate_api_error

    pending = ApprovalGateError(
        "approval_gate_pulse_pending",
        "Approve in the YID app.",
        status=202,
        details={"pulse_request_id": "azr_1", "pulse_match_code": "ABC123"},
    )
    mapped = approval_gate_api_error(pending, status=423, code="approval_required")
    assert mapped.status == 202
    assert mapped.to_payload()["error"] == "approval_gate_pulse_pending"
    assert mapped.to_payload()["pulse_request_id"] == "azr_1"
    other = approval_gate_api_error(
        ApprovalGateError("approval_gate_invalid_password", "Wrong password."), status=423, code="approval_required"
    )
    assert other.status == 423
    assert other.to_payload()["error"] == "approval_required", "other refusals are unchanged"
    assert "pulse_request_id" not in other.to_payload()


def test_a_resubmit_with_an_approved_request_drops_the_password() -> None:
    gate_input = input_from_mapping(
        {"approval_password": "pw", "approval_totp_code": "123456", "approval_pulse_request_id": "azr_1"}
    )
    assert gate_input is not None
    assert (gate_input.password, gate_input.totp_code, gate_input.pulse_request_id) == (None, None, "azr_1")
    kept = input_from_mapping({"approval_password": "pw"})
    assert kept is not None and kept.password == "pw", "without Pulse the password is the proof"


def test_every_resident_call_for_one_action_uses_the_callers_clock(tmp_path: Path, resident) -> None:
    fake = resident(FakeResident(["pending", "approved"]))
    approval_gate.require_approval_decision(
        tmp_path,
        action="allow",
        scope="workspace",
        approval_gate_input=ApprovalGateInput(pulse_mode="wait"),
        now="2026-10-02T00:00:00+00:00",
    )
    clocks = {method: kwargs.get("now") for method, kwargs in fake.calls}
    assert set(clocks) == {"require_approval_decision", "pulse_request", "pulse_poll"}
    assert set(clocks.values()) == {"2026-10-02T00:00:00+00:00"}


def test_the_approval_password_is_sent_as_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import approval_pulse_commands as commands

    typed = iter(["  pass with spaces  ", "  yak_key  ", "   "])
    monkeypatch.setattr(commands.getpass, "getpass", lambda _prompt: next(typed))
    assert commands._password() == "  pass with spaces  "
    assert commands._hidden("YID agent key: ") == "yak_key"
    with pytest.raises(ApprovalGateError):
        commands._password()


@pytest.mark.parametrize("argv", [["--json", "status"], ["status", "--json"]])
def test_json_works_before_or_after_the_subcommand(argv: list[str]) -> None:
    import argparse

    from codex_plugin_scanner.guard.cli.approval_pulse_commands import add_approval_pulse_parser

    root = argparse.ArgumentParser()
    settings = root.add_subparsers(dest="settings_command")
    add_approval_pulse_parser(settings, lambda parser, **_: None, argparse.ArgumentParser)
    assert root.parse_args(["approval-pulse", *argv]).json is True
    assert root.parse_args(["approval-pulse", "status"]).json is False


# Michael's review of #7352: every Pulse-protected settings change names its own
# operation. The resident derives the binding from the change the caller names;
# the Pulse request round trip and the derivation are covered in Rust
# (approval_gate_pulse_binding_tests.rs, approval_gate_settings_binding_tests.rs).
# These check the Python side names the change and that the real resident
# enforces the binding when the change is applied.

_PASSWORD = "correct horse battery"


def _password_gate(guard_home: Path) -> None:
    approval_gate.update_settings(
        guard_home, {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD}
    )


_PULSE_DISABLE = {"kind": "pulse_disable"}
_RESET = {"kind": "reset"}


def _channel(update_channel: str) -> dict[str, object]:
    return {"kind": "update_channel", "update_channel": update_channel}


def _grant_for(guard_home: Path, change: dict[str, object] | None) -> object:
    return approval_gate.require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        settings_change=change,
    )


def test_a_settings_grant_applies_only_the_change_it_was_issued_for(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.config import (
        load_guard_config,
        reset_guard_settings,
        update_guard_update_channel,
    )

    _password_gate(tmp_path)
    to_alpha = _channel("alpha")
    for binding in (None, _PULSE_DISABLE, _RESET, _channel("stable")):
        with pytest.raises(ApprovalGateError):
            update_guard_update_channel(tmp_path, "alpha", approval_gate_grant=_grant_for(tmp_path, binding))
    assert load_guard_config(tmp_path).update_channel == "stable", "no refused grant changed the channel"
    for binding in (None, _PULSE_DISABLE, to_alpha):
        with pytest.raises(ApprovalGateError):
            reset_guard_settings(tmp_path, approval_gate_grant=_grant_for(tmp_path, binding))

    update_guard_update_channel(tmp_path, "alpha", approval_gate_grant=_grant_for(tmp_path, to_alpha))
    assert load_guard_config(tmp_path).update_channel == "alpha"
    reset_guard_settings(tmp_path, approval_gate_grant=_grant_for(tmp_path, _RESET))


def test_each_settings_route_asks_for_its_own_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    import urllib.error
    import urllib.request

    from codex_plugin_scanner.guard.daemon import GuardDaemonServer, server_control_pulse, server_control_repair
    from codex_plugin_scanner.guard.store import GuardStore

    asked: dict[str, object] = {}

    def recorder(route: str):
        def gate(*_args: object, **kwargs: object) -> None:
            assert kwargs.get("action") is None and kwargs.get("subject") is None, "the resident derives the binding"
            asked[route] = kwargs.get("settings_change")
            raise ApprovalGateError("approval_gate_required", "stop here")

        return gate

    daemon = GuardDaemonServer(GuardStore(tmp_path / "home"), host="127.0.0.1", port=0)
    daemon.start()
    try:
        for route, path, body in (
            ("save", "/v1/settings", {"settings": {"receipt_redaction_level": "none"}}),
            ("stable", "/v1/update/channel", {"update_channel": "stable"}),
            ("alpha", "/v1/update/channel", {"update_channel": "alpha"}),
            ("reset", "/v1/settings/reset", {"confirm": "reset-local-settings"}),
            ("disable", "/v1/approval-gate/pulse/disable", {}),
        ):
            module = server_control_pulse if route == "disable" else server_control_repair
            monkeypatch.setattr(module, "require_high_risk", recorder(route))
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}{path}",
                data=json.dumps({**body, "approval_pulse_request_id": "azr_1"}).encode(),
                headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5).close()
            except urllib.error.HTTPError as error:
                error.close()
    finally:
        daemon.stop()
    assert set(asked) == {"save", "stable", "alpha", "reset", "disable"}, asked
    assert all(isinstance(change, dict) for change in asked.values()), asked
    assert len({json.dumps(change, sort_keys=True) for change in asked.values()}) == len(asked), (
        f"two routes name the same change: {asked}"
    )
    assert {change["kind"] for change in asked.values()} == {"save", "update_channel", "reset", "pulse_disable"}
    assert asked["save"] == {"kind": "save", "settings": {"receipt_redaction_level": "none"}}
    assert asked["alpha"] == _channel("alpha")


def test_the_cli_and_the_dashboard_turn_pulse_off_under_the_binding_the_resident_requires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import approval_pulse_commands

    asked: list[object] = []

    def gate(*_args: object, **kwargs: object) -> None:
        asked.append(kwargs.get("settings_change"))
        raise ApprovalGateError("approval_gate_required", "stop here")

    monkeypatch.setattr(approval_pulse_commands, "prompt_for_approval_gate", lambda *_a, **_k: None)
    monkeypatch.setattr(approval_pulse_commands, "require_high_risk", gate)
    with pytest.raises(ApprovalGateError):
        approval_pulse_commands._disable(tmp_path)
    # The resident binds this change to what its disable_pulse consumer requires.
    assert asked == [_PULSE_DISABLE]


# Links to Yanez from the CLI (#7490).


@pytest.mark.parametrize("command", [[], ["status"], ["enroll"], ["disable"], ["recover"]])
def test_every_pulse_command_help_says_where_to_get_the_app_and_read_more(
    command: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    from codex_plugin_scanner.guard.cli.approval_pulse_commands import add_approval_pulse_parser

    root = argparse.ArgumentParser()
    settings = root.add_subparsers(dest="settings_command")
    add_approval_pulse_parser(settings, lambda parser, **_: None, argparse.ArgumentParser)
    with pytest.raises(SystemExit):
        root.parse_args(["approval-pulse", *command, "--help"])
    shown = capsys.readouterr().out
    assert "Get the YID app:  https://pulse.yanez.ai/?referrer_id=holguard\n" in shown
    assert "How Pulse works:  https://docs.yanez.ai/pulse/\n" in shown


def test_cli_setup_sends_new_users_to_the_yid_app_page() -> None:
    from urllib.parse import parse_qs, urlsplit

    from codex_plugin_scanner.guard.cli.approval_pulse_commands import _SETUP_STEPS, PULSE_SITE_URL

    link = urlsplit(PULSE_SITE_URL)
    assert (link.scheme, link.netloc) == ("https", "pulse.yanez.ai")
    assert parse_qs(link.query) == {"referrer_id": ["holguard"]}, "only the HOL Guard referrer, nothing about the user"
    assert any(PULSE_SITE_URL in line for line in _SETUP_STEPS), "setup shows the app link"
    assert not any("docs.yanez.ai" in line for line in _SETUP_STEPS), "setup does not send new users to developer docs"
