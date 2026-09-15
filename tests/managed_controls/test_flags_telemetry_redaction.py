from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.feature_flags import (
    GUARD_EXTENSION_CATALOG_SYNC_V1,
    GUARD_EXTENSION_FIRST_CONTROLS_UI,
    GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1,
    GUARD_MANAGED_EXTENSION_CONTROLS_V1,
    GUARD_POLICY_EXTENSION_TARGETS_V1,
    ManagedControlsFeatureFlags,
)
from codex_plugin_scanner.guard.managed_controls.redaction import (
    redact_managed_controls,
)
from codex_plugin_scanner.guard.managed_controls.telemetry import (
    TelemetryPrivacyError,
    managed_controls_telemetry_event,
)


def test_feature_flags_can_disable_each_pipeline_stage() -> None:
    ManagedControlsFeatureFlags().validate()
    with pytest.raises(ValueError):
        ManagedControlsFeatureFlags(enforcement=True).validate()


def test_managed_control_environment_flags_default_and_malformed_values_fail_closed(monkeypatch) -> None:
    names = (
        GUARD_EXTENSION_CATALOG_SYNC_V1,
        GUARD_POLICY_EXTENSION_TARGETS_V1,
        GUARD_MANAGED_EXTENSION_CONTROLS_V1,
        GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1,
        GUARD_EXTENSION_FIRST_CONTROLS_UI,
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)
    assert ManagedControlsFeatureFlags.from_environment().runtime_capabilities(protected_authority=True) == ()
    for name in names:
        monkeypatch.setenv(name, "enabled")
    flags = ManagedControlsFeatureFlags.from_environment()
    assert flags.runtime_capabilities(protected_authority=True) == ()
    assert flags.allows_custom_extension_continuity() is False


def test_each_managed_control_flag_is_independent_and_prerequisites_fail_closed(monkeypatch) -> None:
    names = (
        GUARD_EXTENSION_CATALOG_SYNC_V1,
        GUARD_POLICY_EXTENSION_TARGETS_V1,
        GUARD_MANAGED_EXTENSION_CONTROLS_V1,
        GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1,
        GUARD_EXTENSION_FIRST_CONTROLS_UI,
    )
    for name in names:
        monkeypatch.setenv(name, "true")
    enabled = ManagedControlsFeatureFlags.from_environment()
    assert enabled.runtime_capabilities(protected_authority=True) == (
        "extension-catalog.v1",
        "extension-control-layer.v1",
        "policy-extension-targets.v1",
        "managed-controls-atomic-apply.v1",
        "custom-extension-continuity.v2",
    )
    assert enabled.allows_custom_extension_continuity() is True
    monkeypatch.setenv(GUARD_EXTENSION_FIRST_CONTROLS_UI, "false")
    without_continuity = ManagedControlsFeatureFlags.from_environment()
    assert "custom-extension-continuity.v2" not in without_continuity.runtime_capabilities(
        protected_authority=True
    )
    monkeypatch.setenv(GUARD_EXTENSION_FIRST_CONTROLS_UI, "true")
    for disabled in names:
        monkeypatch.setenv(disabled, "false")
        flags = ManagedControlsFeatureFlags.from_environment()
        if disabled == GUARD_EXTENSION_CATALOG_SYNC_V1:
            assert flags.runtime_capabilities(protected_authority=True) == ()
        else:
            assert disabled not in {
                GUARD_EXTENSION_CATALOG_SYNC_V1,
            }
        assert flags.allows_custom_extension_continuity() is False
        monkeypatch.setenv(disabled, "true")


def test_telemetry_is_allowlisted_and_privacy_safe() -> None:
    assert managed_controls_telemetry_event({"event": "apply", "result": "success"}) == {
        "event": "apply",
        "result": "success",
    }
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"raw_command": "cat .env"})
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": "https://user:secret@example.test"})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("event", "customer-acme"),
        ("result", "workspace-123"),
        ("control_count_bucket", "102"),
        ("latency_bucket", "123ms"),
    ),
)
def test_telemetry_rejects_noncanonical_identifiers(field: str, value: str) -> None:
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({field: value})


@pytest.mark.parametrize("depth", (1, 8, 64))
def test_telemetry_rejects_bounded_recursive_payloads(depth: int) -> None:
    nested: object = "sensitive"
    for _ in range(depth):
        nested = {"token": nested}
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": nested})


def test_telemetry_accepts_only_canonical_buckets() -> None:
    assert managed_controls_telemetry_event(
        {"event": "drift_check", "result": "blocked", "control_count_bucket": 0}
    ) == {"event": "drift_check", "result": "blocked", "control_count_bucket": "0"}


def test_diagnostics_redact_sensitive_values_recursively() -> None:
    assert redact_managed_controls({"extension_id": "command.git", "proof": "sensitive"}) == {
        "extension_id": "command.git",
        "proof": "[REDACTED]",
    }
    assert redact_managed_controls({"access_token": "sensitive", "workspace_path": "/private"}) == {
        "access_token": "[REDACTED]",
        "workspace_path": "[REDACTED]",
    }
