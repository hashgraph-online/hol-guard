"""Privacy floors remain effective when local settings cannot supply a safe default."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicy, ManagedPolicyState
from codex_plugin_scanner.guard.runtime import receipt_upload
from codex_plugin_scanner.guard.runtime.workspace_preferences import effective_receipt_redaction_level
from codex_plugin_scanner.guard.workspace_preference_authority import capture_workspace_preference_state
from tests.test_receipt_signed_redaction_default import _ready_store, _signed_level


@pytest.mark.parametrize("raw", ['"invalid"', "true", "7"])
def test_invalid_explicit_local_level_never_becomes_an_absent_default(tmp_path: Path, raw: str) -> None:
    store = _ready_store(tmp_path)
    _signed_level(store, "none")
    (store.guard_home / "config.toml").write_text(
        f"sync = true\ntelemetry = true\nreceipt_redaction_level = {raw}\n", encoding="utf-8"
    )
    assert config_module.load_guard_config(store.guard_home).receipt_redaction_level == "full"

    state = capture_workspace_preference_state(store)
    assert receipt_upload.optional_upload_settings(store, state) == (False, "full")
    assert effective_receipt_redaction_level(store) == "full"


@pytest.mark.parametrize("error", [PermissionError, OSError, FileNotFoundError])
def test_unreadable_existing_config_cannot_become_an_absent_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[OSError]
) -> None:
    store = _ready_store(tmp_path, local="full")
    _signed_level(store, "none")
    config_path = store.guard_home / "config.toml"
    original_open = Path.open
    state = capture_workspace_preference_state(store)

    def unreadable(path: Path, *args, **kwargs):
        if path == config_path:
            raise error("synthetic unreadable local configuration")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unreadable)

    assert receipt_upload.optional_upload_settings(store, state) == (False, "full")
    assert effective_receipt_redaction_level(store) == "full"


def test_malformed_local_config_cannot_become_an_absent_default(tmp_path: Path) -> None:
    store = _ready_store(tmp_path)
    _signed_level(store, "none")
    state = capture_workspace_preference_state(store)
    (store.guard_home / "config.toml").write_text("receipt_redaction_level = [", encoding="utf-8")

    assert receipt_upload.optional_upload_settings(store, state) == (False, "full")
    assert effective_receipt_redaction_level(store) == "full"


def test_new_explicit_floor_uses_current_value_instead_of_older_loaded_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ready_store(tmp_path, local="none")
    _signed_level(store, "none")
    original_load = config_module.load_guard_config
    observed: list[str] = []

    def strengthen_after_load(guard_home: Path) -> config_module.GuardConfig:
        configured = original_load(guard_home)
        observed.append(configured.receipt_redaction_level)
        (guard_home / "config.toml").write_text(
            'sync = true\ntelemetry = true\nreceipt_redaction_level = "full"\n', encoding="utf-8"
        )
        return configured

    monkeypatch.setattr(receipt_upload, "load_guard_config", strengthen_after_load)
    state = capture_workspace_preference_state(store)

    assert receipt_upload.optional_upload_settings(store, state) == (True, "full")
    assert observed == ["none"]
    assert effective_receipt_redaction_level(store) == "full"


def test_explicit_local_floor_survives_a_less_restrictive_managed_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ready_store(tmp_path, local="full")
    _signed_level(store, "none")
    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={"receipt_redaction_level": "none"},
        locked_settings=frozenset({"receipt_redaction_level"}),
    )
    managed = ManagedPolicyState("active", "synthetic-component-fixture", policy)
    monkeypatch.setattr(config_module, "load_managed_policy", lambda: managed)
    assert config_module.load_guard_config(store.guard_home).receipt_redaction_level == "none"
    state = capture_workspace_preference_state(store)

    assert receipt_upload.optional_upload_settings(store, state) == (True, "full")
    assert effective_receipt_redaction_level(store) == "full"


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered"])
def test_unavailable_managed_policy_cannot_relax_receipt_privacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    store = _ready_store(tmp_path, local="none")
    _signed_level(store, "none")
    managed = ManagedPolicyState(status, "synthetic-component-fixture")
    monkeypatch.setattr(config_module, "load_managed_policy", lambda: managed)
    state = capture_workspace_preference_state(store)

    assert receipt_upload.optional_upload_settings(store, state) == (False, "full")
    assert effective_receipt_redaction_level(store) == "full"


def test_absent_local_config_keeps_consent_off_while_accepting_verified_signed_setting(
    tmp_path: Path,
) -> None:
    store = _ready_store(tmp_path)
    _signed_level(store, "none")
    state = capture_workspace_preference_state(store)
    (store.guard_home / "config.toml").unlink()

    assert receipt_upload.optional_upload_settings(store, state) == (False, "none")
    assert effective_receipt_redaction_level(store) == "none"
