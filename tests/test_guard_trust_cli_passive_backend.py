"""Regression tests for passive Guard trust backend behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.cli import commands_dispatch_trust as trust_dispatch_module
from codex_plugin_scanner.guard.local_trust_contract import TrustStatus
from codex_plugin_scanner.guard.local_trust_controller import _trust_mode_for_backend
from codex_plugin_scanner.guard.store import SystemKeyringSecretStore


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)


def _enable_macos_native_policy_integrity(
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
):
    fake_keyring = install_fake_system_keyring()
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: True),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_get_secret_without_macos_ui",
        lambda self, secret_id: fake_keyring.get_password(self.service_name, secret_id),
    )
    return fake_keyring


def test_trust_cli_reports_unsupported_backend_status_without_prompt_error(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "status",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["mode"] == "unsupported"
    assert payload["backend_requested"] == "macos-native"
    assert payload["message"].startswith("This local trust backend is unsupported")
    assert payload["passive_prompt_allowed"] is False


def test_trust_cli_degraded_safe_backend_is_explicit(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "status",
            "--backend",
            "degraded-safe",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["backend_requested"] == "degraded-safe"
    assert payload["backend"] == "degraded-safe"
    assert payload["remembered_rules"] == "disabled_degraded"
    assert payload["durable_local_rules"] == "limited"


def test_trust_cli_macos_native_status_reports_setup_required_when_passive_backend_is_ready(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
) -> None:
    _enable_macos_native_policy_integrity(monkeypatch, install_fake_system_keyring)
    home_dir = tmp_path / "home"

    rc = main(
        [
            "guard",
            "trust",
            "status",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["mode"] == "setup_required"
    assert payload["backend_requested"] == "macos-native"
    assert payload["backend_selected"] == "macos-native"
    assert payload["setup_available"] is True
    assert payload["passive_prompt_allowed"] is False


def test_trust_cli_macos_native_test_stays_prompt_free_when_backend_is_unavailable(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    monkeypatch.setattr(trust_dispatch_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: False),
    )

    rc = main(
        [
            "guard",
            "trust",
            "test",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--no-ui",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["mode"] == "degraded_safe"
    assert payload["ok"] is True
    assert payload["trust_health"] == "degraded_safe"
    assert payload["passive_prompt_allowed"] is False


def test_trust_mode_can_report_protected_even_for_degraded_safe_request() -> None:
    trust_status = TrustStatus(
        runtime_protection="protected",
        remembered_rules="enforced",
        cloud_policies="available",
        backend="degraded-safe",
    )

    assert (
        _trust_mode_for_backend(
            trust_status,
            backend_requested="degraded-safe",
            backend_selected="degraded-safe",
            backend_supported=True,
            passive_no_ui_safe=True,
        )
        == "protected"
    )
