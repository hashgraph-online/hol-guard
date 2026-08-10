"""Regression coverage for short-lived, session-bound TOTP reuse."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard import approval_gate as approval_gate_module
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    recent_totp_satisfied,
    require_approval_decision,
)
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.cli import approval_gate_prompt as approval_gate_prompt_module
from codex_plugin_scanner.guard.totp import totp_code_at_counter

PASSWORD = "correct-password"


def _counter(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() // 30)


def _extract_secret(otpauth_uri: str) -> str:
    parsed = urlparse(otpauth_uri)
    values = parse_qs(parsed.query).get("secret")
    if not values:
        raise AssertionError("otpauth URI did not include a secret")
    return values[0]


def _enable_gate(guard_home: Path) -> None:
    update_approval_gate_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": 0,
        },
    )


def _enable_totp(guard_home: Path, *, now: str) -> str:
    enrollment = begin_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="recent-mfa-test",
        now=now,
    )
    secret = _extract_secret(str(enrollment["otpauth_uri"]))
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    confirm_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=code),
        now=now,
    )
    return secret


def _satisfy_totp(guard_home: Path, *, secret: str, now: str) -> str:
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    grant = require_approval_decision(
        guard_home,
        action="allow",
        scope="artifact",
        subject="first-action",
        approval_gate_input=ApprovalGateInput(totp_code=code),
        now=now,
    )
    assert grant is not None
    assert grant.factor_set == ("totp",)
    assert grant.totp_verified is True
    return code


def test_recent_totp_proof_reuses_factor_without_replaying_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-a")
    _enable_gate(guard_home)
    secret = _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")

    first_code = _satisfy_totp(guard_home, secret=secret, now="2026-04-11T00:00:31+00:00")
    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:00:45+00:00") is True

    reused = require_approval_decision(
        guard_home,
        action="allow",
        scope="global",
        subject="follow-on-action",
        approval_gate_input=None,
        now="2026-04-11T00:00:45+00:00",
    )
    assert reused is not None
    assert reused.factor_set == ("totp",)
    assert reused.totp_verified is True
    assert reused.strict is True

    with pytest.raises(ApprovalGateError) as replay_error:
        require_approval_decision(
            guard_home,
            action="allow",
            scope="artifact",
            subject="explicit-replay",
            approval_gate_input=ApprovalGateInput(totp_code=first_code),
            now="2026-04-11T00:00:46+00:00",
        )
    assert replay_error.value.code == "approval_gate_totp_invalid"


def test_recent_totp_proof_is_bound_to_local_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-a")
    _enable_gate(guard_home)
    secret = _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")
    _satisfy_totp(guard_home, secret=secret, now="2026-04-11T00:00:31+00:00")

    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-b")
    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:00:45+00:00") is False
    with pytest.raises(ApprovalGateError) as error:
        require_approval_decision(
            guard_home,
            action="allow",
            scope="artifact",
            approval_gate_input=None,
            now="2026-04-11T00:00:45+00:00",
        )
    assert error.value.code == "approval_gate_totp_required"


def test_recent_totp_proof_expires_after_sixty_seconds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-a")
    _enable_gate(guard_home)
    secret = _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")
    _satisfy_totp(guard_home, secret=secret, now="2026-04-11T00:00:31+00:00")

    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:01:30+00:00") is True
    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:01:31+00:00") is False
    with pytest.raises(ApprovalGateError) as error:
        require_approval_decision(
            guard_home,
            action="allow",
            scope="artifact",
            approval_gate_input=None,
            now="2026-04-11T00:01:31+00:00",
        )
    assert error.value.code == "approval_gate_totp_required"


def test_recent_totp_proof_tampering_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-a")
    _enable_gate(guard_home)
    secret = _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")
    _satisfy_totp(guard_home, secret=secret, now="2026-04-11T00:00:31+00:00")

    state_path = guard_home / "approval-gate.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    proof = state["totp_recent_proof"]
    proof["payload"]["expires_at"] = "2099-01-01T00:00:00+00:00"
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:00:45+00:00") is False
    with pytest.raises(ApprovalGateError) as error:
        require_approval_decision(
            guard_home,
            action="allow",
            scope="artifact",
            approval_gate_input=None,
            now="2026-04-11T00:00:45+00:00",
        )
    assert error.value.code == "approval_gate_totp_required"


def test_totp_enrollment_alone_does_not_create_recent_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(approval_gate_module, "_current_totp_session_binding", lambda: "session-a")
    _enable_gate(guard_home)
    _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")

    assert recent_totp_satisfied(guard_home, now="2026-04-11T00:00:01+00:00") is False


def test_cli_prompt_skips_interaction_when_recent_totp_is_satisfied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    _enable_gate(guard_home)
    _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")
    monkeypatch.setattr(approval_gate_prompt_module, "recent_totp_satisfied", lambda _guard_home: True)
    monkeypatch.setattr(approval_gate_prompt_module.sys.stdin, "isatty", lambda: False)

    assert approval_gate_prompt_module.prompt_for_approval_gate(guard_home) is None
