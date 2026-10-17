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
    assert (
        "Optionally connect an `Authenticator app`; once enabled, its code replaces the `Approval password` "
        "for every protected action and disables cooldown."
    ) in warning
    assert "Authy" not in warning
    assert "This notice is advisory and does not block the current command." in warning


def test_lifecycle_gate_does_not_warn_when_totp_gate_is_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error_stream = io.StringIO()
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(commands_lifecycle_gate, "canonical_lifecycle_home", lambda: tmp_path)
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "public_config",
        lambda _home: SimpleNamespace(enabled=True, totp_enabled=True, cooldown_seconds=900),
    )
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "prompt_for_approval_gate",
        lambda _home, **_kwargs: ApprovalGateInput(totp_code="synthetic-totp-code"),
    )
    monkeypatch.setattr(
        commands_lifecycle_gate,
        "require_high_risk",
        lambda _home, **kwargs: captured.append(kwargs),
    )

    enforce_lifecycle_gate(
        argparse.Namespace(guard_command="doctor", repair=True),
        guard_home=tmp_path,
        error_stream=error_stream,
    )

    assert error_stream.getvalue() == ""
    assert len(captured) == 1
    gate_input = captured[0]["approval_gate_input"]
    assert isinstance(gate_input, ApprovalGateInput)
    assert gate_input.totp_code == "synthetic-totp-code"


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


def test_approval_prompt_tells_the_user_it_is_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.cli.approval_gate_prompt import prompt_for_approval_gate

    password = "correct horse battery staple"
    _ = update_settings(
        tmp_path,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: password)

    result = prompt_for_approval_gate(tmp_path)

    assert result is not None
    assert result.password == password
    assert "waiting for your approval password" in capsys.readouterr().err


def test_silent_authority_names_the_runtime_install_when_the_runtime_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import update_commands

    manual = 'python -m pip install --force-reinstall --no-deps "https://example.test/hol_guard.whl"'
    monkeypatch.setattr(
        update_commands,
        "bundled_native_runtime_report",
        lambda: {"status": "missing", "bundled": False, "manual_install": manual},
    )
    error = ApprovalGateError("native_approval_gate_unavailable", "The native approval authority did not answer.")

    explained = commands_lifecycle_gate.explain_missing_native_runtime(error)

    assert explained.code == "native_approval_gate_unavailable"
    assert manual in str(explained)
    assert "Retry" not in str(explained)


@pytest.mark.parametrize(
    ("code", "report"),
    [
        ("native_approval_gate_unavailable", {"status": "present", "bundled": True}),
        ("native_approval_gate_unavailable", None),
        ("approval_gate_password_required", {"status": "missing", "manual_install": "python -m pip install x"}),
    ],
)
def test_silent_authority_keeps_its_error_unless_the_runtime_is_missing(
    monkeypatch: pytest.MonkeyPatch, code: str, report: dict[str, object] | None
) -> None:
    from codex_plugin_scanner.guard.cli import update_commands

    monkeypatch.setattr(update_commands, "bundled_native_runtime_report", lambda: report)
    error = ApprovalGateError(code, "original")

    assert commands_lifecycle_gate.explain_missing_native_runtime(error) is error


def _missing_runtime(monkeypatch: pytest.MonkeyPatch, repair: tuple[dict[str, object], int] | None) -> list[Path]:
    from codex_plugin_scanner.guard.cli import update_commands

    runtime = {"missing": True}
    calls: list[Path] = []

    def fake_repair(**kwargs: object) -> tuple[dict[str, object], int] | None:
        calls.append(cast(Path, kwargs["guard_home"]))
        if repair is not None and repair[1] == 0:
            runtime["missing"] = False
        return repair

    monkeypatch.setattr(update_commands, "bundled_native_runtime_missing", lambda: runtime["missing"])
    monkeypatch.setattr(update_commands, "repair_native_runtime_if_missing", fake_repair)
    return calls


def test_silent_authority_installs_the_missing_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _missing_runtime(monkeypatch, ({"status": "updated"}, 0))
    error = ApprovalGateError("native_approval_gate_unavailable", "silent")
    stream = io.StringIO()

    restored = commands_lifecycle_gate.restore_missing_native_runtime(
        error, context=None, guard_home=tmp_path, error_stream=stream
    )

    assert restored is True
    assert calls == [tmp_path]
    assert "Installing the missing native runtime" in stream.getvalue()


@pytest.mark.parametrize(
    ("code", "repair"),
    [
        ("approval_gate_password_required", ({"status": "updated"}, 0)),
        ("native_approval_gate_unavailable", ({"status": "failed"}, 1)),
        ("native_approval_gate_unavailable", None),
    ],
)
def test_silent_authority_restore_leaves_other_failures_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: str, repair: tuple[dict[str, object], int] | None
) -> None:
    calls = _missing_runtime(monkeypatch, repair)

    restored = commands_lifecycle_gate.restore_missing_native_runtime(
        ApprovalGateError(code, "original"), context=None, guard_home=tmp_path, error_stream=io.StringIO()
    )

    assert restored is False
    assert calls == ([] if code != "native_approval_gate_unavailable" else [tmp_path])


def test_router_reruns_the_gate_after_restoring_the_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli import commands_router

    gate_calls: list[str] = []

    def gate(_args: object, **_kwargs: object) -> None:
        gate_calls.append("gate")
        if len(gate_calls) == 1:
            raise ApprovalGateError("native_approval_gate_unavailable", "silent")
        raise ApprovalGateError("approval_gate_interactive_required", "approve first")

    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", gate)
    monkeypatch.setattr(commands_router, "restore_missing_native_runtime", lambda *_a, **_k: True)
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(["update", "--guard-home", str(tmp_path), "--json"])
    output = io.StringIO()

    exit_code = run_guard_command(args, output_stream=output)

    assert exit_code == 4
    assert gate_calls == ["gate", "gate"]
    assert cast(dict[str, object], json.loads(output.getvalue()))["error"] == "approval_gate_interactive_required"
