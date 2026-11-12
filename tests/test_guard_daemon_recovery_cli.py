from __future__ import annotations

import argparse
import io
import json
import os
import sys
import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.cli.approval_gate_prompt import consume_desktop_lifecycle_stdin
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import (
    LifecycleGateContext,
    lifecycle_gate_requirement,
)
from codex_plugin_scanner.guard.native_recovery_store import persist_recovery_snapshot


def _current_owner_marker() -> str:
    return f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user"


def _snapshot(operation_id: uuid.UUID, *, phase: str = "complete") -> dict[str, object]:
    terminal = phase == "complete"
    return {
        "schema": "hol-guard-recovery.v1",
        "capabilities": ["diagnostics", "inspect", "restart", "status"],
        "operationId": str(operation_id),
        "sequence": 1,
        "startedAt": "2026-09-20T12:00:00+00:00",
        "updatedAt": "2026-09-20T12:00:01+00:00",
        "phase": phase,
        "activeElapsedMs": 1000,
        "workerActive": False,
        "retryAllowed": terminal,
        "outcome": "restarted" if terminal else "not_recovered",
        "reasonCode": "healthy" if terminal else "approval_required",
        "service": "ready" if terminal else "unknown",
        "protection": "verified" if terminal else "unknown",
        "requiresHumanAction": not terminal,
        "checks": ([{"id": "protection_health", "result": "pass", "reasonCode": "healthy"}] if terminal else []),
    }


def test_restart_lifecycle_gate_is_strict() -> None:
    args = argparse.Namespace(
        guard_command="daemon",
        daemon_command="recovery",
        daemon_recovery_command="restart",
        dry_run=False,
    )
    requirement = lifecycle_gate_requirement(args)
    assert requirement is not None
    assert requirement.action == "daemon.restart"
    assert requirement.subject == "local-daemon"


def test_private_status_survives_a_new_dispatch(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    persist_recovery_snapshot(tmp_path, _snapshot(operation_id))
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 0
    assert json.loads(output.getvalue())["operationId"] == str(operation_id)


def test_status_rejects_cross_operation_lookup(tmp_path: Path) -> None:
    persist_recovery_snapshot(tmp_path, _snapshot(uuid.uuid4()))
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(uuid.uuid4())),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert "recovery failed" in error.getvalue()


def test_restart_rejects_invalid_request_id_without_mutation(tmp_path: Path) -> None:
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id="not-a-uuid", json_lines=True),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert not (tmp_path / "native-runtime" / "daemon-user-recovery.json").exists()


def test_direct_restart_dispatch_fails_closed_without_lifecycle_authorization(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id=str(operation_id), json_lines=False),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 2
    assert "awaiting_approval" in output.getvalue()


def test_direct_restart_rejects_legacy_authorization_without_gate_context(tmp_path: Path) -> None:
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id=str(uuid.uuid4()), json_lines=False),
        guard_home=tmp_path,
        home_dir=None,
        lifecycle_authorized=True,
        stdout=output,
    )
    assert result == 2
    assert "awaiting_approval" in output.getvalue()


@pytest.mark.parametrize(
    ("authority_home_kind", "action", "scope", "subject"),
    [
        ("guard", "daemon.stop", "local-protection", "local-daemon"),
        ("guard", "daemon.restart", "other-scope", "local-daemon"),
        ("guard", "daemon.restart", "local-protection", "other-daemon"),
        ("other", "daemon.restart", "local-protection", "local-daemon"),
    ],
    ids=["wrong-action", "wrong-scope", "wrong-subject", "wrong-authority-home"],
)
def test_direct_restart_rejects_valid_grant_outside_recovery_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_home_kind: str,
    action: str,
    scope: str,
    subject: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    authority_home = guard_home if authority_home_kind == "guard" else tmp_path / "other-home"
    guard_home.mkdir()
    authority_home.mkdir(exist_ok=True)
    password = "correct horse battery staple"
    update_settings(
        authority_home,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    grant = require_high_risk(
        authority_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=password),
        action=action,
        scope=scope,
        subject=subject,
    )
    assert grant is not None
    context = LifecycleGateContext(
        authority_home=authority_home,
        action=action,
        scope=scope,
        subject=subject,
        grant=grant,
        was_enabled=True,
    )
    decisions: list[bool] = []

    def fake_recovery(
        _home: Path, _home_dir: object, mode: str, *, request_id: object = None, authorize=None, emit=None
    ) -> dict[str, object]:
        del emit
        assert mode == "run" and authorize is not None
        allowed = authorize()["allowed"] is True
        decisions.append(allowed)
        return _snapshot(uuid.UUID(str(request_id)), phase="complete" if allowed else "awaiting_approval")

    monkeypatch.setattr(cli, "_native_recovery", fake_recovery)
    output = io.StringIO()
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(
            daemon_recovery_command="restart",
            request_id=str(uuid.uuid4()),
            json_lines=False,
        ),
        guard_home=guard_home,
        home_dir=None,
        lifecycle_authorized=True,
        lifecycle_context=context,
        stdout=output,
        stderr=error,
    )

    assert result == 2
    assert decisions == [False]
    assert "awaiting_approval" in output.getvalue()
    assert error.getvalue() == ""


def test_status_returns_zero_for_a_valid_human_action_snapshot(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    persist_recovery_snapshot(tmp_path, _snapshot(operation_id, phase="awaiting_approval"))
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=io.StringIO(),
    )
    assert result == 0


def test_restart_exit_codes_distinguish_human_action_and_owned_work() -> None:
    operation_id = uuid.uuid4()
    approval = _snapshot(operation_id, phase="awaiting_approval")
    busy = dict(approval, phase="waiting_for_owner", requiresHumanAction=False)
    assert cli._restart_exit_code(approval) == 2
    assert cli._restart_exit_code(busy) == 3


def _proof_stdin(monkeypatch: object, payload: bytes) -> None:
    stream = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)  # type: ignore[attr-defined]


def test_recovery_stdin_uses_totp_instead_of_password(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":null,"totpCode":" 123456 "}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=True)
    assert proof is not None
    assert proof.password is None
    assert proof.totp_code == "123456"


def test_recovery_stdin_uses_password_without_totp(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"correct horse","totpCode":null}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=False)
    assert proof is not None
    assert proof.password == "correct horse"
    assert proof.totp_code is None


def test_recovery_stdin_rejects_conflicting_or_unbounded_proof(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"one","totpCode":"123456"}')
    with pytest.raises(ApprovalGateError, match="never both"):
        consume_desktop_lifecycle_stdin(totp_enabled=True)
    _proof_stdin(monkeypatch, b"x" * (4 * 1024 + 1))
    with pytest.raises(ApprovalGateError, match="exceeded"):
        consume_desktop_lifecycle_stdin(totp_enabled=False)


@pytest.mark.parametrize("payload", [b"", b"not-json", b"{}", b'{"password":null,"totpCode":null}'])
def test_recovery_stdin_rejects_missing_or_malformed_proof(monkeypatch: object, payload: bytes) -> None:
    _proof_stdin(monkeypatch, payload)
    with pytest.raises(ApprovalGateError):
        consume_desktop_lifecycle_stdin(totp_enabled=False)
