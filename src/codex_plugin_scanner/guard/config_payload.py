"""Pure construction from already-read configuration; no file or policy reload."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .mdm.contracts import ManagedPolicy, ManagedPolicyState
from .presentation_mode import coerce_persisted_presentation_mode
from .protection_posture import (
    coerce_loaded_protection_posture,
    coerce_watch_auto_revert_hours,
    derive_protection_posture,
)

if TYPE_CHECKING:
    from .config import GuardConfig


def guard_config_from_payload(
    guard_home: Path,
    workspace: Path | None,
    merged: dict[str, object],
    managed_state: ManagedPolicyState,
    effective_managed_policy: ManagedPolicy | None,
) -> GuardConfig:
    from .config import (
        DEFAULT_SECURITY_LEVEL,
        PRESENTATION_SCHEMA_VERSION,
        GuardConfig,
        _coerce_action_map,
        _coerce_harness_risk_action_map,
        _coerce_loaded_approval_browser_severity,
        _coerce_loaded_approval_surface_policy,
        _coerce_loaded_bool,
        _coerce_loaded_bounded_int,
        _coerce_loaded_bounded_positive_int,
        _coerce_loaded_guard_action_or_default,
        _coerce_loaded_guard_mode,
        _coerce_loaded_non_negative_int,
        _coerce_loaded_optional_bounded_positive_int,
        _coerce_loaded_positive_int,
        _coerce_loaded_receipt_redaction_level,
        _coerce_loaded_security_level,
        _coerce_loaded_string_tuple,
        _coerce_loaded_update_channel,
        _coerce_risk_action_map,
        _coerce_sandbox_analysis,
        _coerce_watch_entered_at,
    )

    loaded_mode = _coerce_loaded_guard_mode(merged.get("mode"), "prompt")
    loaded_security_level = _coerce_loaded_security_level(merged.get("security_level", DEFAULT_SECURITY_LEVEL))
    explicit_posture = coerce_loaded_protection_posture(merged.get("protection_posture"))
    managed_locks_level = (
        effective_managed_policy is not None and "security_level" in effective_managed_policy.locked_settings
    )
    if managed_locks_level:
        loaded_posture = derive_protection_posture(loaded_mode, loaded_security_level)
        posture_explicit = False
    elif explicit_posture is not None:
        loaded_posture = explicit_posture
        posture_explicit = True
    else:
        loaded_posture = derive_protection_posture(loaded_mode, loaded_security_level)
        posture_explicit = False
    legacy_presentation_value = next(
        (
            merged.get(key)
            for key in ("presentation_mode", "presentation_density", "display_density", "density")
            if merged.get(key) is not None
        ),
        None,
    )
    persisted_presentation = coerce_persisted_presentation_mode(
        legacy_presentation_value,
        explicit=merged.get("presentation_mode_explicit", legacy_presentation_value is not None),
        schema_version=merged.get("presentation_schema_version", PRESENTATION_SCHEMA_VERSION),
    )
    presentation_revision = _coerce_loaded_non_negative_int(merged.get("presentation_revision"), 0)
    return GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        mode=("observe" if loaded_posture == "watch" else loaded_mode),
        presentation_mode=persisted_presentation.value,
        presentation_mode_explicit=persisted_presentation.explicit,
        presentation_schema_version=persisted_presentation.schema_version,
        presentation_revision=presentation_revision,
        presentation_source=persisted_presentation.source,
        presentation_diagnostic=persisted_presentation.diagnostic,
        protection_posture=loaded_posture,
        protection_posture_explicit=posture_explicit,
        watch_auto_revert_hours=coerce_watch_auto_revert_hours(merged.get("watch_auto_revert_hours")),
        watch_entered_at=_coerce_watch_entered_at(merged.get("watch_entered_at")),
        default_action=_coerce_loaded_guard_action_or_default(merged.get("default_action"), "warn"),
        unknown_publisher_action=_coerce_loaded_guard_action_or_default(
            merged.get("unknown_publisher_action"),
            "review",
        ),
        changed_hash_action=_coerce_loaded_guard_action_or_default(
            merged.get("changed_hash_action"),
            "require-reapproval",
        ),
        new_network_domain_action=_coerce_loaded_guard_action_or_default(
            merged.get("new_network_domain_action"),
            "warn",
        ),
        subprocess_action=_coerce_loaded_guard_action_or_default(merged.get("subprocess_action"), "warn"),
        approval_wait_timeout_seconds=_coerce_loaded_non_negative_int(
            merged.get("approval_wait_timeout_seconds"),
            120,
        ),
        approval_surface_policy=_coerce_loaded_approval_surface_policy(merged.get("approval_surface_policy")),
        approval_browser_delay_seconds=_coerce_loaded_bounded_int(
            merged.get("approval_browser_delay_seconds"),
            default=20,
            maximum=300,
        ),
        approval_browser_immediate_severity=_coerce_loaded_approval_browser_severity(
            merged.get("approval_browser_immediate_severity")
        ),
        desktop_notifications=_coerce_loaded_bool(merged.get("desktop_notifications", True)),
        update_channel=_coerce_loaded_update_channel(merged.get("update_channel")),
        telemetry=bool(merged.get("telemetry", False)),
        sync=bool(merged.get("sync", False)),
        billing=bool(merged.get("billing", False)),
        runtime_detector_registry=_coerce_loaded_bool(merged.get("runtime_detector_registry", False)),
        runtime_detector_timeout_ms=_coerce_loaded_positive_int(merged.get("runtime_detector_timeout_ms", 50), 50),
        runtime_detector_debug_trace=_coerce_loaded_bool(merged.get("runtime_detector_debug_trace", False)),
        runtime_detector_disabled_ids=_coerce_loaded_string_tuple(merged.get("runtime_detector_disabled_ids")),
        sandbox_analysis=_coerce_sandbox_analysis(merged.get("sandbox_analysis", "off")),
        harness_actions=_coerce_action_map(merged.get("harnesses")),
        publisher_actions=_coerce_action_map(merged.get("publishers")),
        artifact_actions=_coerce_action_map(merged.get("artifacts")),
        security_level=loaded_security_level,
        risk_actions=_coerce_risk_action_map(merged.get("risk_actions")),
        harness_risk_actions=_coerce_harness_risk_action_map(merged.get("harness_risk_actions")),
        receipt_redaction_level=_coerce_loaded_receipt_redaction_level(
            merged.get("receipt_redaction_level"),
        ),
        evidence_retain_days=_coerce_loaded_bounded_positive_int(
            merged.get("evidence_retain_days"),
            default=90,
            maximum=3_650,
        ),
        receipt_detail_limit=_coerce_loaded_optional_bounded_positive_int(
            merged.get("receipt_detail_limit"),
            maximum=1_000_000,
        ),
        guard_event_limit=_coerce_loaded_optional_bounded_positive_int(
            merged.get("guard_event_limit"),
            maximum=1_000_000,
        ),
        managed_policy_status=managed_state.status,
        managed_policy_hash=effective_managed_policy.content_hash if effective_managed_policy is not None else None,
        managed_locked_settings=tuple(sorted(effective_managed_policy.locked_settings))
        if effective_managed_policy is not None
        else (),
        install_owner=effective_managed_policy.install_owner if effective_managed_policy is not None else "user",
        managed_policy=effective_managed_policy,
    )
