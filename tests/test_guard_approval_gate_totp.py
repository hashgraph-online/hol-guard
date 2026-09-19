"""TOTP enrollment, replay, grants and concurrent proof use."""

from __future__ import annotations

import io
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    public_config,
    require_approval_decision,
    validate_grant,
)
from codex_plugin_scanner.guard.cli.commands import run_guard_command
from codex_plugin_scanner.guard.totp import _temporary_atomic_path, totp_code_at_counter
from tests.guard_approval_gate_support import (
    PASSWORD,
    WRONG_PASSWORD,
    _add_request,
    _approve,
    _counter,
    _enable_gate,
    _enable_totp,
    _store,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
)


def test_totp_atomic_temp_paths_are_random(tmp_path: Path) -> None:
    target_path = tmp_path / "guard-home" / "totp-secrets" / "seed.secret"
    first = _temporary_atomic_path(target_path)
    second = _temporary_atomic_path(target_path)
    try:
        assert first != second
        assert first.parent == target_path.parent
        assert second.parent == target_path.parent
        assert first.name != f"{target_path.name}.tmp"
        assert second.name != f"{target_path.name}.tmp"
    finally:
        if first.exists():
            first.unlink()
        if second.exists():
            second.unlink()


def test_approval_gate_totp_enrollment_sets_pending_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    now = "2026-04-11T00:00:00+00:00"

    enrollment = begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="test-device",
        now=now,
    )

    assert enrollment["pending"] is True
    assert str(enrollment["otpauth_uri"]).startswith("otpauth://totp/HOL%20Guard:test-device?")
    assert "issuer=HOL%20Guard" in str(enrollment["otpauth_uri"])
    gate = public_config(store.guard_home, now=now)
    assert gate.totp_pending is True
    assert gate.totp_enabled is False


def test_approval_gate_totp_invalid_code_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    now = "2026-04-11T00:00:00+00:00"
    begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        now=now,
    )

    with pytest.raises(ApprovalGateError) as error:
        confirm_totp_enrollment(
            store.guard_home,
            approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code="000000"),
            now=now,
        )

    assert error.value.code == "approval_gate_totp_invalid"
    gate = public_config(store.guard_home, now=now)
    assert gate.totp_pending is True
    assert gate.totp_enabled is False


def test_approval_gate_totp_replay_rejected_and_next_step_succeeds(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    enrollment_now = "2026-04-11T00:00:00+00:00"
    secret = _enable_totp(store, now=enrollment_now)
    replay_code = totp_code_at_counter(secret=secret, counter=_counter(enrollment_now))

    _add_request(store, "req-totp-replay")
    with pytest.raises(ApprovalGateError) as replay_error:
        _approve(
            store,
            "req-totp-replay",
            gate_input=ApprovalGateInput(password=PASSWORD, totp_code=replay_code),
            now="2026-04-11T00:00:01+00:00",
        )
    assert replay_error.value.code == "approval_gate_totp_invalid"

    _add_request(store, "req-totp-next-step")
    next_now = "2026-04-11T00:00:31+00:00"
    next_code = totp_code_at_counter(secret=secret, counter=_counter(next_now))
    _approve(
        store,
        "req-totp-next-step",
        gate_input=ApprovalGateInput(password=PASSWORD, totp_code=next_code),
        now=next_now,
    )
    assert store.get_approval_request("req-totp-next-step")["status"] == "resolved"


def test_approval_gate_totp_clock_skew_boundary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    skew_now = "2026-04-11T00:01:01+00:00"
    previous_step_code = totp_code_at_counter(secret=secret, counter=_counter(skew_now) - 1)
    _add_request(store, "req-totp-skew-accept")
    _approve(
        store,
        "req-totp-skew-accept",
        gate_input=ApprovalGateInput(password=PASSWORD, totp_code=previous_step_code),
        now=skew_now,
    )

    old_code = totp_code_at_counter(secret=secret, counter=_counter(skew_now) - 2)
    _add_request(store, "req-totp-skew-reject")
    with pytest.raises(ApprovalGateError) as old_error:
        _approve(
            store,
            "req-totp-skew-reject",
            gate_input=ApprovalGateInput(password=PASSWORD, totp_code=old_code),
            now=skew_now,
        )
    assert old_error.value.code == "approval_gate_totp_invalid"


def test_approval_gate_totp_manual_key_accepts_readability_dashes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    dashed_secret = "-".join(secret[index : index + 4] for index in range(0, len(secret), 4))

    assert totp_code_at_counter(secret=dashed_secret, counter=_counter("2026-04-11T00:01:00+00:00"))


def test_approval_gate_disable_totp_requires_totp_only_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    with pytest.raises(ApprovalGateError) as missing_totp:
        disable_totp(store.guard_home, approval_gate_input=ApprovalGateInput(), now="2026-04-11T00:00:31+00:00")
    assert missing_totp.value.code == "approval_gate_totp_required"

    disable_now = "2026-04-11T00:01:31+00:00"
    disable_code = totp_code_at_counter(secret=secret, counter=_counter(disable_now))
    with pytest.raises(ApprovalGateError) as invalid_totp:
        disable_totp(
            store.guard_home,
            approval_gate_input=ApprovalGateInput(totp_code="000000"),
            now=disable_now,
        )
    assert invalid_totp.value.code == "approval_gate_totp_invalid"

    gate = disable_totp(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(totp_code=disable_code),
        now=disable_now,
    )
    assert gate.totp_enabled is False


def test_approval_gate_password_disable_requires_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home_dir = tmp_path / "home"
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")

    disable_without_totp = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="disable",
            current_password=None,
            totp_code=None,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_without_totp == 4

    disable_now = datetime.now(timezone.utc).isoformat()
    disable_code = totp_code_at_counter(secret=secret, counter=_counter(disable_now))
    disable_with_totp = run_guard_command(
        SimpleNamespace(
            guard_command="settings",
            settings_command="approval-password",
            settings_approval_password_command="disable",
            current_password=None,
            totp_code=disable_code,
            guard_home=str(store.guard_home),
            home=str(home_dir),
            workspace=str(workspace),
            json=True,
            cisco_mode="off",
        ),
        output_stream=io.StringIO(),
    )
    assert disable_with_totp == 0
    assert public_config(store.guard_home).enabled is False


def test_approval_gate_totp_overrides_password_for_reviews(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    approve_now = "2026-04-11T00:00:31+00:00"
    approve_code = totp_code_at_counter(secret=secret, counter=_counter(approve_now))
    _add_request(store, "req-totp-only")

    _approve(
        store,
        "req-totp-only",
        gate_input=ApprovalGateInput(password=WRONG_PASSWORD, totp_code=approve_code),
        now=approve_now,
    )

    assert store.get_approval_request("req-totp-only")["status"] == "resolved"


def test_approval_gate_totp_grant_is_context_bound_and_expires(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    issued_at = "2026-04-11T00:00:31+00:00"
    code = totp_code_at_counter(secret=secret, counter=_counter(issued_at))

    grant = require_approval_decision(
        store.guard_home,
        action="allow",
        scope="artifact",
        subject="approval-request:req-bound",
        session_nonce="dashboard-session-1",
        approval_gate_input=ApprovalGateInput(totp_code=code),
        now=issued_at,
    )

    assert grant is not None
    assert grant.password_verified is False
    assert grant.totp_verified is True
    assert grant.factor_set == ("totp",)
    assert grant.action == "allow"
    assert grant.scope == "artifact"
    assert grant.subject == "approval-request:req-bound"
    assert grant.session_nonce == "dashboard-session-1"
    validate_grant(
        store.guard_home,
        grant,
        purpose="approval_decision",
        strict=False,
        action="allow",
        scope="artifact",
        subject="approval-request:req-bound",
        session_nonce="dashboard-session-1",
        now="2026-04-11T00:00:45+00:00",
    )

    with pytest.raises(ApprovalGateError, match="does not match this subject"):
        validate_grant(
            store.guard_home,
            grant,
            purpose="approval_decision",
            strict=False,
            subject="approval-request:req-other",
            now="2026-04-11T00:00:45+00:00",
        )
    with pytest.raises(ApprovalGateError, match="proof is invalid"):
        validate_grant(
            store.guard_home,
            replace(grant, action="block"),
            purpose="approval_decision",
            strict=False,
            now="2026-04-11T00:00:45+00:00",
        )
    with pytest.raises(ApprovalGateError) as expired:
        validate_grant(
            store.guard_home,
            grant,
            purpose="approval_decision",
            strict=False,
            now="2026-04-11T00:01:02+00:00",
        )
    assert expired.value.code == "approval_gate_grant_expired"


def test_approval_gate_totp_disable_revokes_outstanding_grants_and_auth_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    grant_now = "2026-04-11T00:00:31+00:00"
    grant_code = totp_code_at_counter(secret=secret, counter=_counter(grant_now))
    grant = require_approval_decision(
        store.guard_home,
        action="allow",
        scope="artifact",
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=grant_code),
        now=grant_now,
    )
    assert grant is not None

    state_path = store.guard_home / "approval-gate.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state.update(
        {
            "approval_sessions": ["stale-session"],
            "recovery_code_hashes": ["stale-code"],
            "trusted_devices": ["stale-device"],
        }
    )
    state_path.write_text(json.dumps(state), encoding="utf-8")
    disable_now = "2026-04-11T00:00:32+00:00"
    next_counter_code = totp_code_at_counter(secret=secret, counter=_counter(disable_now) + 1)
    disable_totp(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=next_counter_code),
        now=disable_now,
    )

    rotated_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert rotated_state["factor_generation"] > state["factor_generation"]
    assert "approval_sessions" not in rotated_state
    assert "recovery_code_hashes" not in rotated_state
    assert "trusted_devices" not in rotated_state
    with pytest.raises(ApprovalGateError, match="Approval proof is required"):
        validate_grant(
            store.guard_home,
            grant,
            purpose="approval_decision",
            strict=False,
            now=disable_now,
        )


def test_approval_gate_tracks_active_totp_failures_and_locks(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    attempt_now = "2026-04-11T00:00:31+00:00"
    _add_request(store, "req-factor-budget")

    for _ in range(4):
        with pytest.raises(ApprovalGateError) as error:
            _approve(
                store,
                "req-factor-budget",
                gate_input=ApprovalGateInput(totp_code="000000"),
                now=attempt_now,
            )
        assert error.value.code == "approval_gate_totp_invalid"

    state = json.loads((store.guard_home / "approval-gate.json").read_text(encoding="utf-8"))
    assert state["password_failed_attempts"] == 0
    assert state["totp_failed_attempts"] == 4
    assert state["failed_attempts"] == 4

    with pytest.raises(ApprovalGateError) as fifth_failure:
        _approve(
            store,
            "req-factor-budget",
            gate_input=ApprovalGateInput(totp_code="000000"),
            now=attempt_now,
        )
    assert fifth_failure.value.code == "approval_gate_totp_invalid"
    with pytest.raises(ApprovalGateError) as locked:
        _approve(
            store,
            "req-factor-budget",
            gate_input=ApprovalGateInput(totp_code=totp_code_at_counter(secret=secret, counter=_counter(attempt_now))),
            now=attempt_now,
        )
    assert locked.value.code == "approval_gate_locked"


def test_approval_gate_concurrent_totp_reuses_recent_session_proof(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    approve_now = "2026-04-11T00:00:31+00:00"
    approve_code = totp_code_at_counter(secret=secret, counter=_counter(approve_now))
    request_ids = ("req-concurrent-a", "req-concurrent-b")
    for request_id in request_ids:
        _add_request(store, request_id)

    def approve(request_id: str) -> str:
        try:
            _approve(
                store,
                request_id,
                gate_input=ApprovalGateInput(password=PASSWORD, totp_code=approve_code),
                now=approve_now,
            )
        except ApprovalGateError as error:
            return error.code
        return "resolved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(approve, request_ids))

    assert outcomes == ["resolved", "resolved"]
    statuses = sorted(str(store.get_approval_request(request_id)["status"]) for request_id in request_ids)
    assert statuses == ["resolved", "resolved"]
