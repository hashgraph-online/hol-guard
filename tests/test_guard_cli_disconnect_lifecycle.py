from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import enforce_lifecycle_gate


def test_lifecycle_gate_uninstall_requires_fresh_totp_even_when_recent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "public_config",
        lambda _home: SimpleNamespace(enabled=True, totp_enabled=True, cooldown_seconds=0),
    )
    monkeypatch.setattr(commands_lifecycle_gate, "recent_totp_satisfied", lambda _home: True)
    monkeypatch.setattr(commands_lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_kwargs: None)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "prompt_for_approval_gate",
        lambda *_args, **_kwargs: ApprovalGateInput(),
    )

    with pytest.raises(ApprovalGateError, match="TOTP code is required"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="uninstall", harness="codex"),
            guard_home=tmp_path,
        )


def test_lifecycle_gate_apps_disconnect_requires_fresh_totp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "public_config",
        lambda _home: SimpleNamespace(enabled=True, totp_enabled=True, cooldown_seconds=0),
    )
    monkeypatch.setattr(commands_lifecycle_gate, "recent_totp_satisfied", lambda _home: True)
    monkeypatch.setattr(commands_lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_kwargs: None)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "prompt_for_approval_gate",
        lambda *_args, **_kwargs: ApprovalGateInput(),
    )

    with pytest.raises(ApprovalGateError, match="TOTP code is required"):
        enforce_lifecycle_gate(
            argparse.Namespace(
                guard_command="apps",
                apps_command="disconnect",
                harness="codex",
                confirm="disconnect-codex",
            ),
            guard_home=tmp_path,
        )


def test_lifecycle_gate_apps_disconnect_skips_totp_until_confirmation_phrase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompted = {"called": False}
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "public_config",
        lambda _home: SimpleNamespace(enabled=True, totp_enabled=True, cooldown_seconds=0),
    )
    monkeypatch.setattr(commands_lifecycle_gate, "recent_totp_satisfied", lambda _home: False)
    monkeypatch.setattr(commands_lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_kwargs: None)

    def unexpected_prompt(*_args: object, **_kwargs: object) -> ApprovalGateInput:
        prompted["called"] = True
        return ApprovalGateInput()

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", unexpected_prompt)

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="apps", apps_command="disconnect", harness="codex"),
        guard_home=tmp_path,
    )

    assert prompted["called"] is False


def test_lifecycle_gate_uninstall_prompt_requests_fresh_totp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompted: dict[str, object] = {}
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "public_config",
        lambda _home: SimpleNamespace(enabled=True, totp_enabled=True, cooldown_seconds=0),
    )
    monkeypatch.setattr(commands_lifecycle_gate, "recent_totp_satisfied", lambda _home: True)
    monkeypatch.setattr(commands_lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_kwargs: None)

    def capture_prompt(*_args: object, **kwargs: object) -> ApprovalGateInput:
        prompted["require_fresh_totp"] = kwargs.get("require_fresh_totp")
        return ApprovalGateInput(totp_code="123456")

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", capture_prompt)
    monkeypatch.setattr(commands_lifecycle_gate, "require_high_risk", lambda _home, **_kwargs: object())

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="uninstall", harness="codex"),
        guard_home=tmp_path,
    )

    assert prompted["require_fresh_totp"] is True
