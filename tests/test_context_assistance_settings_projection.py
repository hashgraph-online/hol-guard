"""The Python presentation layer uses the native portable preference view."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.config import GuardConfig, editable_guard_settings
from codex_plugin_scanner.guard.daemon.server_common import _settings_export_payload
from codex_plugin_scanner.guard.native_policy_effective import _config_fields


@pytest.fixture(autouse=True)
def synthetic_approval_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Presentation of configuration must not read the real machine's gate.
    monkeypatch.setattr(config_module, "public_config", lambda _: SimpleNamespace(to_dict=lambda: {}))


def test_local_settings_preserve_native_requested_preferences_and_diagnostic(tmp_path: Path) -> None:
    preferences = {"enabled": False, "runtime_id": "runtime-1"}
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        context_assistance=preferences,
        context_assistance_diagnostic="context_assistance_schema_invalid",
    )

    settings = editable_guard_settings(config)

    assert settings["context_assistance"] == preferences
    assert settings["context_assistance_diagnostic"] == "context_assistance_schema_invalid"
    assert "context_assistance_export" not in settings
    assert "effective_enabled" not in settings


def test_export_uses_native_portable_view_instead_of_private_local_selection(tmp_path: Path) -> None:
    local = {
        "enabled": True,
        "runtime_id": "private-runtime",
        "sources": {"workspace_documents": True, "source_set_id": "private-source-set"},
    }
    portable = {
        "enabled": False,
        "runtime_id": "",
        "sources": {"workspace_documents": False, "source_set_id": ""},
    }
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        context_assistance=local,
        context_assistance_requested=local,
        context_assistance_requested_available=True,
        context_assistance_export=portable,
        context_assistance_diagnostic="context_assistance_schema_invalid",
    )

    exported = _settings_export_payload(config)
    settings = exported["settings"]

    assert isinstance(settings, dict)
    assert settings["context_assistance"] == portable
    assert "context_assistance_diagnostic" not in settings
    assert "context_assistance_requested" not in settings
    assert "private-runtime" not in str(exported)
    assert "private-source-set" not in str(exported)
    assert config.context_assistance == local


def test_absent_portable_projection_is_omitted_instead_of_exporting_local_access(tmp_path: Path) -> None:
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        context_assistance={"enabled": True, "runtime_id": "private-runtime"},
    )

    exported = _settings_export_payload(config)
    settings = exported["settings"]

    assert isinstance(settings, dict)
    assert "context_assistance" not in settings
    assert "private-runtime" not in str(exported)


def test_default_settings_export_remains_importable_without_assistance(tmp_path: Path) -> None:
    config = GuardConfig(guard_home=tmp_path, workspace=None)

    exported = _settings_export_payload(config)
    settings = exported["settings"]

    assert isinstance(settings, dict)
    assert "context_assistance" not in settings
    assert settings["mode"] == "prompt"
    assert settings["security_level"] == "balanced"


def test_assistance_preferences_do_not_enter_the_native_enforcement_policy_request(tmp_path: Path) -> None:
    baseline = GuardConfig(guard_home=tmp_path, workspace=None)
    configured = replace(
        baseline,
        context_assistance={"enabled": True, "runtime_id": "runtime-1"},
        context_assistance_diagnostic="context_assistance_schema_invalid",
        context_assistance_export={"enabled": False, "runtime_id": ""},
    )

    assert _config_fields(configured) == _config_fields(baseline)


def test_restricted_effective_settings_do_not_replace_saved_local_intent(tmp_path: Path) -> None:
    requested = {"enabled": True, "runtime_id": "runtime-1"}
    effective = {"enabled": False, "runtime_id": "runtime-1"}
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        context_assistance=effective,
        context_assistance_requested=requested,
        context_assistance_requested_available=True,
    )
    settings = editable_guard_settings(config)
    assert settings["context_assistance"] == requested
    assert settings["context_assistance_requested"] == requested
    assert config.context_assistance == effective
    assert _config_fields(config) == _config_fields(GuardConfig(guard_home=tmp_path, workspace=None))


def test_older_native_core_keeps_base_guard_available_without_optional_assistance_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = GuardConfig(guard_home=tmp_path, workspace=None)
    loaded = {
        key: getattr(baseline, key)
        for key in config_module._NATIVE_LOADED_FIELDS
        if key not in config_module._OPTIONAL_ASSISTANCE_FIELDS
    }
    monkeypatch.setattr(config_module, "load_native_guard_config", lambda *args, **kwargs: dict(loaded))
    managed = SimpleNamespace(policy=None, status="unmanaged")
    result = config_module.load_guard_config(tmp_path, managed_policy_state=managed, create_home=False)
    assert result.mode == baseline.mode
    assert result.context_assistance_requested_available is False
    assert "context_assistance_requested" not in editable_guard_settings(result)
    for key in ("mode", "approval_wait_timeout_seconds"):
        missing = loaded.pop(key)
        with pytest.raises(config_module.ConfigFileTrustError, match="native_guard_config_invalid"):
            config_module.load_guard_config(tmp_path, managed_policy_state=managed, create_home=False)
        loaded[key] = missing
    loaded["unrecognized_authority"] = True
    with pytest.raises(config_module.ConfigFileTrustError, match="native_guard_config_invalid"):
        config_module.load_guard_config(tmp_path, managed_policy_state=managed, create_home=False)
