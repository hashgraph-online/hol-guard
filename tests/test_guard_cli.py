"""Guard CLI settings and command parsing behavior."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.config import load_guard_config, resolve_risk_action
from tests.guard_cli_fixture_support import _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


def test_guard_help_uses_ai_antivirus_product_language() -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    guard_commands_module.add_guard_root_parser(parser)

    help_text = parser.format_help()

    assert "AI Antivirus" in help_text
    assert "Home" in help_text
    assert "Protect" in help_text
    assert "Inbox" in help_text
    assert "Evidence" in help_text
    assert "Settings" in help_text
    assert "init" in help_text
    assert "Watched Apps" not in help_text


def test_guard_cli_parses_approval_password_and_unlock_lock_commands() -> None:
    parser = argparse.ArgumentParser(prog="hol-guard")
    guard_commands_module.add_guard_root_parser(parser)

    status_args = parser.parse_args(["settings", "approval-password", "status"])
    enable_args = parser.parse_args(
        [
            "settings",
            "approval-password",
            "enable",
            "--new-password",
            "hunter42!",
            "--confirm-password",
            "hunter42!",
        ]
    )
    unlock_args = parser.parse_args(["approvals", "unlock", "--duration", "1h"])
    lock_args = parser.parse_args(["approvals", "lock"])
    totp_status_args = parser.parse_args(["settings", "approval-totp", "status"])
    totp_enroll_args = parser.parse_args(
        [
            "settings",
            "approval-totp",
            "enroll",
            "--current-password",
            "hunter42!",
            "--device-label",
            "my-device",
        ]
    )
    totp_verify_args = parser.parse_args(
        [
            "settings",
            "approval-totp",
            "verify",
            "--current-password",
            "hunter42!",
            "--code",
            "123456",
        ]
    )
    totp_disable_args = parser.parse_args(
        [
            "settings",
            "approval-totp",
            "disable",
            "--current-password",
            "hunter42!",
            "--code",
            "123456",
        ]
    )

    assert status_args.settings_command == "approval-password"
    assert status_args.settings_approval_password_command == "status"
    assert enable_args.settings_approval_password_command == "enable"
    assert unlock_args.approvals_command == "unlock"
    assert lock_args.approvals_command == "lock"
    assert totp_status_args.settings_command == "approval-totp"
    assert totp_status_args.settings_approval_totp_command == "status"
    assert totp_enroll_args.settings_approval_totp_command == "enroll"
    assert totp_verify_args.settings_approval_totp_command == "verify"
    assert totp_disable_args.settings_approval_totp_command == "disable"


def test_guard_settings_show_and_update_security_level(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(
        home_dir / "config.toml",
        "\n".join(
            [
                'security_level = "custom"',
                "",
                "[risk_actions]",
                'local_secret_read = "allow"',
                "",
                "[harness_risk_actions.codex]",
                'local_secret_read = "allow"',
            ]
        )
        + "\n",
    )

    show_rc = main(["guard", "settings", "--home", str(home_dir), "--json"])
    show_payload = json.loads(capsys.readouterr().out)

    assert show_rc == 0
    assert show_payload["settings"]["security_level"] == "custom"

    set_rc = main(["guard", "settings", "set", "security-level", "strict", "--home", str(home_dir), "--json"])
    set_payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert set_rc == 0
    assert set_payload["settings"]["security_level"] == "strict"
    assert loaded.security_level == "strict"
    assert loaded.risk_actions == {}
    assert loaded.harness_risk_actions == {}
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "require-reapproval"


def test_guard_settings_cli_payload_omits_billing_flag(tmp_path):
    home_dir = tmp_path / "home"
    config = load_guard_config(home_dir)

    payload = guard_commands_module._guard_cli_settings_payload(config)

    assert isinstance(payload["settings"], dict)
    assert "billing" not in payload["settings"]


def test_guard_settings_set_security_level_custom_preserves_current_effective_risks(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "strict"\n')

    rc = main(["guard", "settings", "set", "security-level", "custom", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["security_level"] == "custom"
    assert loaded.security_level == "custom"
    assert loaded.risk_actions["network_egress"] == "require-reapproval"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"


def test_guard_settings_set_risk_action_for_harness(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "strict"\n')

    rc = main(
        [
            "guard",
            "settings",
            "set",
            "risk",
            "local-secret-read",
            "allow",
            "--harness",
            "Codex",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["harness_risk_actions"]["codex"]["local_secret_read"] == "allow"
    assert loaded.security_level == "strict"
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"


def test_guard_settings_set_global_risk_action_preserves_preset_defaults(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(
        home_dir / "config.toml",
        "\n".join(
            [
                'security_level = "strict"',
                "",
                "[risk_actions]",
                'encoded_execution = "block"',
            ]
        )
        + "\n",
    )

    rc = main(
        [
            "guard",
            "settings",
            "set",
            "risk",
            "local-secret-read",
            "allow",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["security_level"] == "strict"
    assert loaded.security_level == "strict"
    assert loaded.risk_actions == {
        "encoded_execution": "block",
        "local_secret_read": "allow",
    }
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "encoded_execution", harness="codex") == "block"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"


def test_guard_settings_set_security_level_gentle(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "balanced"\n')

    rc = main(["guard", "settings", "set", "security-level", "gentle", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["security_level"] == "gentle"
    assert loaded.security_level == "gentle"
    assert loaded.risk_actions == {}
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "warn"


def test_guard_settings_set_security_level_paranoid(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "balanced"\n')

    rc = main(["guard", "settings", "set", "security-level", "paranoid", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["security_level"] == "paranoid"
    assert loaded.security_level == "paranoid"
    assert loaded.risk_actions == {}
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "block"
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "block"


def test_guard_settings_set_preset_command(tmp_path, capsys):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "custom"\n')

    rc = main(["guard", "settings", "set", "preset", "strict", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["security_level"] == "strict"
    assert loaded.security_level == "strict"
    assert resolve_risk_action(loaded, "data_flow_exfiltration", harness="codex") == "block"


def test_guard_settings_set_secret_files(tmp_path, capsys):
    home_dir = tmp_path / "home"

    rc = main(["guard", "settings", "set", "secret-files", "allow", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert loaded.risk_actions is not None
    assert loaded.risk_actions.get("local_secret_read") == "allow"
    _ = payload


def test_guard_settings_set_network(tmp_path, capsys):
    home_dir = tmp_path / "home"

    rc = main(["guard", "settings", "set", "network", "block", "--home", str(home_dir), "--json"])
    json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert loaded.risk_actions is not None
    assert loaded.risk_actions.get("network_egress") == "block"


def test_guard_settings_set_encoded_payloads(tmp_path, capsys):
    home_dir = tmp_path / "home"

    rc = main(["guard", "settings", "set", "encoded-payloads", "block", "--home", str(home_dir), "--json"])
    json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert loaded.risk_actions is not None
    assert loaded.risk_actions.get("encoded_execution") == "block"
    assert loaded.risk_actions.get("encoded_exfiltration") == "block"


@pytest.mark.parametrize(
    ("command", "policy", "risk_key", "expected_action"),
    [
        ("mcp", "ask-all", "mcp_dangerous_tool", "require-reapproval"),
        ("skills", "ask-dangerous", "malicious_skill", "require-reapproval"),
        ("packages", "ask-lifecycle", "package_script", "require-reapproval"),
        ("output-scanning", "ask", "encoded_exfiltration", "require-reapproval"),
    ],
)
def test_guard_settings_specialized_policy_commands_update_risk_actions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    policy: str,
    risk_key: str,
    expected_action: str,
):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "gentle"\n')

    rc = main(["guard", "settings", "set", command, policy, "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    loaded = load_guard_config(home_dir)

    assert rc == 0
    assert payload["settings"]["risk_actions"][risk_key] == expected_action
    assert resolve_risk_action(loaded, risk_key, harness="codex") == expected_action


def test_guard_config_migration_old_config_lacking_new_risk_keys(tmp_path):
    home_dir = tmp_path / "home"
    _write_text(
        home_dir / "config.toml",
        "\n".join(
            [
                'security_level = "balanced"',
                "",
                "[risk_actions]",
                'local_secret_read = "allow"',
                'network_egress = "warn"',
            ]
        )
        + "\n",
    )

    loaded = load_guard_config(home_dir)

    assert loaded.security_level == "balanced"
    assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "allow"
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "warn"
    assert resolve_risk_action(loaded, "prompt_injection", harness="codex") == "require-reapproval"
    assert resolve_risk_action(loaded, "guard_bypass", harness="codex") == "block"


def test_guard_config_validation_rejects_unknown_preset(tmp_path):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "ultra-strict"\n')

    loaded = load_guard_config(home_dir)

    assert loaded.security_level == "balanced"


def test_guard_settings_new_risk_keys_in_paranoid_preset(tmp_path):
    home_dir = tmp_path / "home"
    _write_text(home_dir / "config.toml", 'security_level = "paranoid"\n')

    loaded = load_guard_config(home_dir)

    assert resolve_risk_action(loaded, "prompt_injection", harness="codex") == "block"
    assert resolve_risk_action(loaded, "mcp_dangerous_tool", harness="codex") == "block"
    assert resolve_risk_action(loaded, "malicious_skill", harness="codex") == "block"
    assert resolve_risk_action(loaded, "guard_bypass", harness="codex") == "block"
    assert resolve_risk_action(loaded, "encoded_exfiltration", harness="codex") == "block"


class _OAuthCredentialsFixture:
    """Original shared OAuth credential fixture for the CLI tests."""

    @staticmethod
    def seed(store, *, now):
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now=now,
        )
