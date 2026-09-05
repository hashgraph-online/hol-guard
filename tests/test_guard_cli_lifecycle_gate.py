from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import (
    enforce_lifecycle_gate,
    lifecycle_gate_requirement,
)
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.cli.commands_router import run_guard_command


@pytest.mark.parametrize(
    ("attributes", "action"),
    [
        ({"guard_command": "install", "harness": "codex"}, "install"),
        ({"guard_command": "uninstall", "all": True}, "uninstall"),
        ({"guard_command": "update"}, "update"),
        ({"guard_command": "apps", "apps_command": "connect", "harness": "pi"}, "apps.connect"),
        ({"guard_command": "bootstrap"}, "bootstrap.install"),
        ({"guard_command": "init"}, "init.install"),
        ({"guard_command": "disconnect", "source": "default"}, "disconnect"),
        ({"guard_command": "device", "device_command": "rotate"}, "device.rotate"),
        ({"guard_command": "commands", "commands_command": "approve", "job_id": "job-1"}, "commands.approve"),
        ({"guard_command": "daemon", "daemon_command": "stop"}, "daemon.stop"),
        ({"guard_command": "trust", "trust_command": "reset"}, "trust.reset"),
        ({"guard_command": "doctor", "repair": True}, "doctor.repair"),
    ],
)
def test_lifecycle_gate_classifies_security_mutations(
    attributes: dict[str, object],
    action: str,
) -> None:
    requirement = lifecycle_gate_requirement(argparse.Namespace(**attributes))

    assert requirement is not None
    assert requirement.action == action


@pytest.mark.parametrize(
    "attributes",
    [
        {"guard_command": "install", "dry_run": True},
        {"guard_command": "apps", "apps_command": "test", "harness": "pi"},
        {"guard_command": "bootstrap", "skip_install": True},
        {"guard_command": "init", "skip_apps": True},
        {"guard_command": "device", "device_command": "show"},
        {"guard_command": "commands", "commands_command": "status"},
        {"guard_command": "daemon", "daemon_command": "repair"},
        {"guard_command": "daemon", "daemon_command": "status"},
        {"guard_command": "trust", "trust_command": "status"},
        {"guard_command": "doctor", "repair": False},
        {"guard_command": "mdm", "mdm_command": "deactivate"},
    ],
)
def test_lifecycle_gate_exempts_read_only_dry_run_and_recovery(
    attributes: dict[str, object],
) -> None:
    assert lifecycle_gate_requirement(argparse.Namespace(**attributes)) is None


def test_lifecycle_gate_warns_and_allows_when_protection_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error_stream = io.StringIO()
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="uninstall", harness="codex"),
        guard_home=tmp_path,
        error_stream=error_stream,
    )

    warning = error_stream.getvalue()
    assert "Local Guard approval protection is not enabled." in warning
    assert "Guard Cloud sign-in and account MFA are separate from this local gate." in warning
    assert "Settings > Approval gate" in warning
    assert "Ask for proof on allow decisions" in warning
    assert "Optionally connect an `Authenticator app` for high-risk approvals." in warning
    assert "Authy" not in warning
    assert "This notice is advisory and does not block the current command." in warning


def test_lifecycle_gate_requires_fresh_password_when_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )

    def wrong_password_prompt(_guard_home: Path, **_kwargs: object) -> ApprovalGateInput:
        return ApprovalGateInput(password="wrong password")

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", wrong_password_prompt)

    with pytest.raises(ApprovalGateError, match="invalid"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="daemon", daemon_command="stop"),
            guard_home=tmp_path,
        )


def test_lifecycle_gate_accepts_valid_password_and_binds_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )

    def valid_password_prompt(_guard_home: Path, **_kwargs: object) -> ApprovalGateInput:
        return ApprovalGateInput(password=password)

    monkeypatch.setattr(commands_lifecycle_gate, "prompt_for_approval_gate", valid_password_prompt)

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="install", harness="codex"),
        guard_home=tmp_path,
    )


@pytest.mark.parametrize("override_flag", ["--home", "--guard-home"])
def test_canonical_gate_blocks_lifecycle_override_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override_flag: str,
) -> None:
    canonical_parent = tmp_path / "canonical"
    alternate_home = tmp_path / "alternate"
    canonical_parent.mkdir()
    monkeypatch.setattr(commands_lifecycle_gate, "trusted_user_home", lambda: canonical_parent)
    monkeypatch.setenv("HOME", str(canonical_parent))
    canonical_home = commands_lifecycle_gate.canonical_lifecycle_home()
    password = "correct horse battery staple"
    _ = update_settings(
        canonical_home,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    handler_called = False

    def update_handler(*_args: object, **_kwargs: object) -> int:
        nonlocal handler_called
        handler_called = True
        return 0

    from codex_plugin_scanner.guard.cli import commands_router

    monkeypatch.setattr(commands_router, "_run_guard_update_command", update_handler, raising=False)
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(["update", override_flag, str(alternate_home), "--json"])
    output = io.StringIO()

    exit_code = run_guard_command(args, output_stream=output)

    assert exit_code == 4
    assert handler_called is False
    payload = cast(dict[str, object], json.loads(output.getvalue()))
    assert payload["error"] == "approval_gate_interactive_required"


def test_canonical_gate_ignores_ambient_home_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_home = tmp_path / "trusted"
    fake_home = tmp_path / "fake"
    trusted_home.mkdir()
    monkeypatch.setattr(commands_lifecycle_gate, "trusted_user_home", lambda: trusted_home)
    monkeypatch.setenv("HOME", str(fake_home))
    canonical_home = commands_lifecycle_gate.canonical_lifecycle_home()
    password = "correct horse battery staple"
    _ = update_settings(
        canonical_home,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with pytest.raises(ApprovalGateError, match="interactive terminal"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="update"),
            guard_home=fake_home / ".hol-guard",
        )


def test_cloud_disconnect_uses_canonical_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical_home = tmp_path / "canonical"
    alternate_home = tmp_path / "alternate"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: canonical_home)
    password = "correct horse battery staple"
    _ = update_settings(
        canonical_home,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with pytest.raises(ApprovalGateError, match="interactive terminal"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="disconnect", source="default"),
            guard_home=alternate_home,
        )


def test_desktop_child_env_password_satisfies_lifecycle_gate_without_tty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", password)

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="update"),
        guard_home=tmp_path,
    )

    assert "HOL_GUARD_APPROVAL_PASSWORD" not in os.environ


def test_desktop_child_env_is_ignored_without_desktop_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", password)

    with pytest.raises(ApprovalGateError, match="interactive terminal"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="update"),
            guard_home=tmp_path,
        )


def test_desktop_child_env_rejects_password_and_totp_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", password)
    monkeypatch.setenv("HOL_GUARD_APPROVAL_TOTP_CODE", "123456")

    with pytest.raises(ApprovalGateError, match="never both"):
        enforce_lifecycle_gate(
            argparse.Namespace(guard_command="update"),
            guard_home=tmp_path,
        )


def test_desktop_child_env_supplies_totp_when_authenticator_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import consume_desktop_lifecycle_env

    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_TOTP_CODE", "123456")

    proof = consume_desktop_lifecycle_env(
        totp_enabled=True,
        use_cooldown=False,
        cooldown_seconds=0,
    )

    assert proof is not None
    assert proof.password is None
    assert proof.totp_code == "123456"
    assert proof.use_cooldown is False
    assert "HOL_GUARD_APPROVAL_TOTP_CODE" not in os.environ


def test_desktop_child_env_is_ignored_outside_lifecycle_enforcement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import prompt_for_approval_gate

    password = "correct horse battery staple"
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", password)

    with pytest.raises(ApprovalGateError, match="interactive terminal"):
        prompt_for_approval_gate(tmp_path)

    assert os.environ.get("HOL_GUARD_APPROVAL_PASSWORD") == password


def test_desktop_child_env_preserves_password_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import consume_desktop_lifecycle_env

    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", " secret ")

    proof = consume_desktop_lifecycle_env(
        totp_enabled=False,
        use_cooldown=False,
        cooldown_seconds=0,
    )

    assert proof is not None
    assert proof.password == " secret "


def test_desktop_child_env_totp_defers_to_recent_session_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_TOTP_CODE", "123456")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_lifecycle_gate.public_config",
        lambda _home: SimpleNamespace(
            enabled=True,
            totp_enabled=True,
            cooldown_seconds=0,
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_lifecycle_gate.recent_totp_satisfied",
        lambda _home: True,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_lifecycle_gate.require_high_risk",
        lambda *_args, **_kwargs: None,
    )

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="update"),
        guard_home=tmp_path,
    )

    assert "HOL_GUARD_APPROVAL_TOTP_CODE" not in os.environ


def test_desktop_child_env_is_cleared_when_the_gate_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", "correct horse battery staple")

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="update"),
        guard_home=tmp_path,
        error_stream=io.StringIO(),
    )

    assert "HOL_GUARD_APPROVAL_PASSWORD" not in os.environ
