"""Guard configuration loading and resolution."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeGuard, cast, get_args

from .approval_gate import ApprovalGateGrant, public_config, require_settings_write
from .approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS  # noqa: F401 - re-exported
from .config_constants import (
    VALID_GUARD_ACTIONS,
    VALID_RISK_ACTION_KEYS,
    VALID_SECURITY_LEVELS,
)
from .config_file_io import ConfigFileTrustError
from .config_mutation import notify_native_policy_mutation, record_posture_change_if_needed
from .harness_posture import (
    HARNESS_POSTURES_KEY,
    effective_harness_postures,
    harness_posture_status,
    harness_watch_auto_revert_due,
    managed_locks_harness_postures,
)
from .mdm.contracts import ManagedPolicy, ManagedPolicyState
from .mdm.policy import fail_closed_managed_policy, load_managed_policy
from .models import GuardAction, GuardMode
from .native_guard_config import (
    load_native_guard_config,
    resolve_native_guard_config,
    update_native_guard_config,
)
from .presentation_mode import PRESENTATION_SCHEMA_VERSION
from .protection_events import record_harness_posture_changes_if_needed
from .protection_posture import (
    DEFAULT_PROTECTION_POSTURE,
    DEFAULT_WATCH_AUTO_REVERT_HOURS,
    VALID_PROTECTION_POSTURES,
)

DEFAULT_GUARD_DIRNAME = ".hol-guard"


def watch_should_auto_revert(config: GuardConfig, *, now: datetime | None = None) -> bool:
    if config.protection_posture != "watch" or config.watch_auto_revert_hours <= 0:
        return False
    if config.watch_entered_at is None:
        return False
    try:
        entered = datetime.fromisoformat(config.watch_entered_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if entered.tzinfo is None:
        entered = entered.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return current - entered >= timedelta(hours=config.watch_auto_revert_hours)


def maybe_auto_revert_watch(guard_home: Path, *, now: datetime | None = None) -> GuardConfig:
    config = load_guard_config(guard_home)
    revert: dict[str, object] = {}
    if watch_should_auto_revert(config, now=now):
        revert["protection_posture"] = "protected"
    if due_harnesses := harness_watch_auto_revert_due(config, now=now):
        # A harness reverts to inheriting the baseline posture.
        revert[HARNESS_POSTURES_KEY] = dict.fromkeys(due_harnesses)
    if not revert:
        return config
    return update_guard_settings(
        guard_home,
        revert,
        event_source="auto-revert",
        skip_approval_gate=True,
    )


LEGACY_GUARD_DIRNAMES = (".config/.ai-plugin-scanner-guard", ".ai-plugin-scanner-guard", ".holguard")
# One legacy home's move can back up a large guard.db; the runtime caps
# each database copy at five seconds.
_GUARD_HOME_RESOLVE_TIMEOUT_SECONDS = 30.0

DEFAULT_SECURITY_LEVEL = "balanced"
VALID_RECEIPT_REDACTION_LEVELS = frozenset({"full", "partial", "none"})


@dataclass(frozen=True, slots=True)
class GuardConfig:
    """Merged local Guard configuration."""

    guard_home: Path
    workspace: Path | None
    mode: GuardMode = "prompt"
    presentation_mode: str = "everyday"
    presentation_mode_explicit: bool = False
    presentation_schema_version: int = PRESENTATION_SCHEMA_VERSION
    presentation_revision: int = 0
    presentation_source: str = "default"
    presentation_diagnostic: str | None = None
    protection_posture: str = DEFAULT_PROTECTION_POSTURE
    protection_posture_explicit: bool = False
    watch_auto_revert_hours: int = DEFAULT_WATCH_AUTO_REVERT_HOURS
    watch_entered_at: str | None = None
    harness_postures: dict[str, str] | None = None
    harness_watch_entered_at: dict[str, str] | None = None
    security_level: str = DEFAULT_SECURITY_LEVEL
    default_action: GuardAction = "warn"
    unknown_publisher_action: GuardAction = "review"
    changed_hash_action: GuardAction = "require-reapproval"
    new_network_domain_action: GuardAction = "warn"
    subprocess_action: GuardAction = "warn"
    approval_wait_timeout_seconds: int = 120
    approval_surface_policy: str = "attention-aware"
    blocked_request_mode: str = "safe-alternative"
    approval_browser_delay_seconds: int = 20
    approval_browser_immediate_severity: str = "critical"
    desktop_notifications: bool = True
    update_channel: str = "stable"
    telemetry: bool = False
    sync: bool = False
    receipt_redaction_level: str = "full"
    billing: bool = False
    context_assistance: dict[str, object] | None = None
    context_assistance_diagnostic: str | None = None
    context_assistance_export: dict[str, object] | None = None
    context_assistance_requested: dict[str, object] | None = None
    context_assistance_requested_available: bool = False
    runtime_detector_registry: bool = False
    runtime_detector_timeout_ms: int = 50
    runtime_detector_debug_trace: bool = False
    runtime_detector_disabled_ids: tuple[str, ...] = ()
    sandbox_analysis: str = "off"
    workspace_assessment_enabled: bool = True
    risk_actions: dict[str, GuardAction] | None = None
    harness_risk_actions: dict[str, dict[str, GuardAction]] | None = None
    harness_actions: dict[str, GuardAction] | None = None
    publisher_actions: dict[str, GuardAction] | None = None
    artifact_actions: dict[str, GuardAction] | None = None
    evidence_retain_days: int = 90
    receipt_detail_limit: int | None = None
    guard_event_limit: int | None = None
    managed_policy_status: str = "absent"
    managed_policy_hash: str | None = None
    managed_locked_settings: tuple[str, ...] = ()
    install_owner: str = "user"
    managed_policy: ManagedPolicy | None = None

    def resolve_action_override(
        self,
        harness: str,
        artifact_id: str | None,
        publisher: str | None,
    ) -> GuardAction | None:
        narrow_override = self.resolve_artifact_or_publisher_action_override(
            artifact_id,
            publisher,
        )
        if narrow_override is not None:
            return narrow_override
        if self.harness_actions is not None and harness in self.harness_actions:
            return self.harness_actions[harness]
        return None

    def resolve_artifact_or_publisher_action_override(
        self,
        artifact_id: str | None,
        publisher: str | None,
    ) -> GuardAction | None:
        if artifact_id is not None and self.artifact_actions is not None and artifact_id in self.artifact_actions:
            return self.artifact_actions[artifact_id]
        if publisher is not None and self.publisher_actions is not None and publisher in self.publisher_actions:
            return self.publisher_actions[publisher]
        return None


_NATIVE_LOADED_FIELDS = frozenset(field.name for field in fields(GuardConfig)) - frozenset(
    {
        "guard_home",
        "workspace",
        "managed_policy_status",
        "managed_policy_hash",
        "managed_locked_settings",
        "install_owner",
        "managed_policy",
        "context_assistance_requested_available",
    }
)

_OPTIONAL_ASSISTANCE_FIELDS = frozenset(
    {
        "context_assistance",
        "context_assistance_diagnostic",
        "context_assistance_export",
        "context_assistance_requested",
    }
)


def resolve_guard_home(override: str | None = None) -> Path:
    """Resolve the Guard home directory."""

    if override:
        return Path(override).expanduser().resolve()
    return resolve_guard_home_for_user_home(Path.home())


def resolve_guard_home_for_user_home(user_home: Path) -> Path:
    """Resolve Guard state beneath an already authenticated user home."""

    canonical_home = user_home / DEFAULT_GUARD_DIRNAME
    legacy_home = _existing_legacy_guard_home(user_home)
    if legacy_home is None:
        return canonical_home
    # `guard_home_resolve.rs` picks between the homes and moves a legacy home
    # with state into the canonical one.
    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        "native-guard-home-resolve-v1",
        "guard-home-resolve",
        {"schema": "guard-home-resolve.v1", "user_home": str(user_home.absolute())},
        output_limit=64 * 1024,
        timeout_seconds=_GUARD_HOME_RESOLVE_TIMEOUT_SECONDS,
    )
    guard_home = None if answer is None else answer.get("guard_home")
    if isinstance(guard_home, str) and guard_home:
        return Path(guard_home)
    # An older runtime: use the canonical home once it exists, the legacy one until then.
    return canonical_home if canonical_home.exists() else legacy_home


def _effective_managed_policy(managed_state: ManagedPolicyState) -> ManagedPolicy | None:
    if managed_state.policy is None and managed_state.status in {"invalid", "inaccessible", "tampered"}:
        return fail_closed_managed_policy()
    return managed_state.policy


def _native_managed_input(policy: ManagedPolicy | None) -> dict[str, object] | None:
    if policy is None:
        return None
    return {"settings": policy.settings, "locked_settings": sorted(policy.locked_settings)}


def load_guard_config(
    guard_home: Path,
    workspace: Path | None = None,
    *,
    managed_policy_state: ManagedPolicyState | None = None,
    require_canonical_workspace: bool = False,
    create_home: bool = True,
) -> GuardConfig:
    """Load Guard config from home and workspace overrides through the native runtime."""

    if create_home:
        guard_home.mkdir(parents=True, exist_ok=True)
    managed_state = managed_policy_state or load_managed_policy()
    effective_managed_policy = _effective_managed_policy(managed_state)
    loaded = load_native_guard_config(
        guard_home,
        workspace,
        require_canonical_workspace=require_canonical_workspace,
        managed=_native_managed_input(effective_managed_policy),
    )
    if not _NATIVE_LOADED_FIELDS - _OPTIONAL_ASSISTANCE_FIELDS <= set(loaded) <= _NATIVE_LOADED_FIELDS:
        raise ConfigFileTrustError("native_guard_config_invalid")
    loaded["runtime_detector_disabled_ids"] = tuple(cast("list[str]", loaded["runtime_detector_disabled_ids"]))
    return GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        context_assistance_requested_available="context_assistance_requested" in loaded,
        **loaded,  # type: ignore[arg-type]
        managed_policy_status=managed_state.status,
        managed_policy_hash=effective_managed_policy.content_hash if effective_managed_policy is not None else None,
        managed_locked_settings=tuple(sorted(effective_managed_policy.locked_settings))
        if effective_managed_policy is not None
        else (),
        install_owner=effective_managed_policy.install_owner if effective_managed_policy is not None else "user",
        managed_policy=effective_managed_policy,
    )


def editable_guard_settings(config: GuardConfig) -> dict[str, object]:
    """Return Guard config values that are safe to edit from the local dashboard."""

    settings: dict[str, object] = {
        "mode": config.mode,
        "presentation_mode": config.presentation_mode,
        "presentation_mode_explicit": config.presentation_mode_explicit,
        "presentation_schema_version": config.presentation_schema_version,
        "presentation_revision": config.presentation_revision,
        "presentation": {
            "value": config.presentation_mode,
            "source": config.presentation_source,
            "explicit": config.presentation_mode_explicit,
            "writable": True,
            "schema_version": config.presentation_schema_version,
            "revision": config.presentation_revision,
            "diagnostic": config.presentation_diagnostic,
        },
        "presentation_diagnostic": config.presentation_diagnostic,
        "protection_posture": config.protection_posture,
        "protection_posture_explicit": config.protection_posture_explicit,
        "watch_auto_revert_hours": config.watch_auto_revert_hours,
        "harness_postures": dict(config.harness_postures or {}),
        "harness_watch_entered_at": dict(config.harness_watch_entered_at or {}),
        "harness_postures_effective": effective_harness_postures(config),
        "harness_posture_status": harness_posture_status(config),
        "harness_postures_locked": managed_locks_harness_postures(config.managed_locked_settings),
        "security_level": config.security_level,
        "default_action": config.default_action,
        "unknown_publisher_action": config.unknown_publisher_action,
        "changed_hash_action": config.changed_hash_action,
        "new_network_domain_action": config.new_network_domain_action,
        "subprocess_action": config.subprocess_action,
        "risk_actions": _effective_risk_actions(config),
        "risk_action_overrides": dict(config.risk_actions or {}),
        "harness_risk_actions": dict(config.harness_risk_actions or {}),
        "approval_wait_timeout_seconds": config.approval_wait_timeout_seconds,
        "approval_surface_policy": config.approval_surface_policy,
        "blocked_request_mode": config.blocked_request_mode,
        "approval_browser_delay_seconds": config.approval_browser_delay_seconds,
        "approval_browser_immediate_severity": config.approval_browser_immediate_severity,
        "desktop_notifications": config.desktop_notifications,
        "update_channel": config.update_channel,
        "telemetry": config.telemetry,
        "sync": config.sync,
        "receipt_redaction_level": config.receipt_redaction_level,
        "billing": config.billing,
        "approval_gate": public_config(config.guard_home).to_dict(),
        "context_assistance": config.context_assistance_requested
        if config.context_assistance_requested_available
        else config.context_assistance,
        "context_assistance_diagnostic": config.context_assistance_diagnostic,
        "managed_policy_status": config.managed_policy_status,
        "managed_policy_hash": config.managed_policy_hash,
        "managed_locked_settings": list(config.managed_locked_settings),
        "install_owner": config.install_owner,
    }
    if config.context_assistance_requested_available:
        settings["context_assistance_requested"] = config.context_assistance_requested
    return settings


# The daemon serves settings writes from a bounded threading HTTP server, so
# the read/validate/write sequence below must be serialized per process to keep
# optimistic presentation-revision checks meaningful.
_GUARD_SETTINGS_WRITE_LOCK = threading.Lock()


def update_guard_settings(
    guard_home: Path,
    payload: dict[str, object],
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    cloud_sync_entitled: bool = False,
    event_source: str = "settings",
    skip_approval_gate: bool = False,
) -> GuardConfig:
    """Persist safe local Guard settings to config.toml and return the updated config."""

    with _GUARD_SETTINGS_WRITE_LOCK:
        return _update_guard_settings_locked(
            guard_home,
            payload,
            approval_gate_grant=approval_gate_grant,
            cloud_sync_entitled=cloud_sync_entitled,
            event_source=event_source,
            skip_approval_gate=skip_approval_gate,
        )


def _update_guard_settings_locked(
    guard_home: Path,
    payload: dict[str, object],
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    cloud_sync_entitled: bool = False,
    event_source: str = "settings",
    skip_approval_gate: bool = False,
) -> GuardConfig:

    if not skip_approval_gate:
        require_settings_write(guard_home, approval_gate_grant=approval_gate_grant)
    previous = update_native_guard_config(
        guard_home,
        "settings",
        payload,
        managed=_native_managed_input(_effective_managed_policy(load_managed_policy())),
        cloud_sync_entitled=cloud_sync_entitled,
    )
    if previous is None:
        raise ConfigFileTrustError("native_guard_config_invalid")
    updated = load_guard_config(guard_home)
    notify_native_policy_mutation(guard_home)
    record_posture_change_if_needed(
        guard_home,
        previous=previous["previous"],
        next_posture=updated.protection_posture,
        previous_explicit=previous["previous_explicit"],
        next_explicit=updated.protection_posture_explicit,
        selected=previous["selected"],
        event_source=event_source,
    )
    record_harness_posture_changes_if_needed(
        guard_home,
        previous=previous["harness_postures"],
        updated=updated.harness_postures or {},
        event_source=event_source,
    )
    return updated


def update_guard_update_channel(
    guard_home: Path,
    update_channel: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> GuardConfig:
    """Persist the local release channel selected from the update surface."""

    require_settings_write(guard_home, approval_gate_grant=approval_gate_grant)
    _write_guard_config_change(guard_home, "channel", update_channel)
    updated = load_guard_config(guard_home)
    notify_native_policy_mutation(guard_home)
    return updated


def reset_guard_settings(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> GuardConfig:
    """Reset editable local Guard settings while preserving non-dashboard config."""

    require_settings_write(guard_home, approval_gate_grant=approval_gate_grant)
    _write_guard_config_change(guard_home, "reset", None)
    updated = load_guard_config(guard_home)
    notify_native_policy_mutation(guard_home)
    return updated


def _write_guard_config_change(guard_home: Path, kind: str, value: object) -> None:
    update_native_guard_config(
        guard_home,
        kind,
        value,
        managed=_native_managed_input(_effective_managed_policy(load_managed_policy())),
    )


def _resolved_risk_actions(config: GuardConfig, harness: str | None) -> dict[str, GuardAction]:
    """Every risk class's action for ``harness``, resolved by the native runtime."""

    result = resolve_native_guard_config(
        "risk_actions",
        {"facts": risk_action_config_facts(config), "harness": harness},
    )
    resolved = result.get("risk_actions")
    # Every risk class must come back with an action: a missing class would
    # read as "no configured action" and skip its floor.
    if not _is_risk_action_map(resolved) or set(resolved) != VALID_RISK_ACTION_KEYS:
        raise ConfigFileTrustError("native_guard_config_invalid")
    return resolved


def _is_risk_action_map(value: object) -> TypeGuard[dict[str, GuardAction]]:
    return isinstance(value, dict) and all(
        isinstance(key, str)
        and key in VALID_RISK_ACTION_KEYS
        and isinstance(action, str)
        and action in VALID_GUARD_ACTIONS
        for key, action in value.items()
    )


def _effective_risk_actions(config: GuardConfig) -> dict[str, GuardAction]:
    return _resolved_risk_actions(config, None)


def risk_action_config_facts(config: GuardConfig) -> dict[str, object]:
    """The configuration fields the resident resolves a risk class under.

    Sent instead of a resolved action so the resident owns the verdict. The
    maps go over as they were loaded: ``harness_risk_actions`` keyed the way
    the caller spells its harness and ``harness_postures`` canonically, which
    is how :func:`resolve_risk_action` reads each of them.
    """

    return {
        "security_level": config.security_level,
        "protection_posture": config.protection_posture,
        "protection_posture_explicit": bool(config.protection_posture_explicit),
        "managed_locked_settings": list(config.managed_locked_settings),
        "risk_actions": dict(config.risk_actions or {}),
        "harness_risk_actions": {name: dict(actions) for name, actions in (config.harness_risk_actions or {}).items()},
        "harness_postures": dict(config.harness_postures or {}),
    }


def resolve_risk_action(config: GuardConfig, risk_class: str | None, *, harness: str | None) -> GuardAction | None:
    """Resolve the configured action for a concrete runtime risk class."""

    if not isinstance(risk_class, str) or risk_class not in VALID_RISK_ACTION_KEYS:
        return None
    return _resolved_risk_actions(config, harness if isinstance(harness, str) else None).get(risk_class)


# The fields composing a synced payload and the managed policy may change.
_OVERLAID_FIELDS = (
    "mode",
    "security_level",
    "protection_posture",
    "protection_posture_explicit",
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
    "risk_actions",
    "harness_risk_actions",
    "telemetry",
    "sync",
    "receipt_redaction_level",
)


def overlay_synced_guard_policy(
    config: GuardConfig,
    payload: dict[str, object] | None,
) -> GuardConfig:
    if not isinstance(payload, dict):
        return config
    return _overlay(config, payload)


def _overlay(config: GuardConfig, payload: dict[str, object] | None) -> GuardConfig:
    """Compose ``payload`` and the managed policy onto ``config`` natively."""

    loaded: dict[str, object] = {name: getattr(config, name) for name in _OVERLAID_FIELDS}
    loaded["risk_actions"] = dict(config.risk_actions or {})
    loaded["harness_risk_actions"] = {
        name: dict(actions) for name, actions in (config.harness_risk_actions or {}).items()
    }
    loaded["managed_locked_settings"] = list(config.managed_locked_settings)
    result = resolve_native_guard_config(
        "overlay",
        {"config": loaded, "payload": payload, "managed": _native_managed_input(config.managed_policy)},
    )
    overlaid = result.get("config")
    if not isinstance(overlaid, dict) or not all(
        name in overlaid and _OVERLAID_FIELD_VALID[name](overlaid[name]) for name in _OVERLAID_FIELDS
    ):
        raise ConfigFileTrustError("native_guard_config_invalid")
    return replace(config, **{name: overlaid[name] for name in _OVERLAID_FIELDS})


def _is_action(value: object) -> bool:
    return isinstance(value, str) and value in VALID_GUARD_ACTIONS


def _is_one_of(allowed: frozenset[str] | set[str]) -> Callable[[object], bool]:
    return lambda value: isinstance(value, str) and value in allowed


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_harness_risk_action_maps(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(name, str) and _is_risk_action_map(actions) for name, actions in value.items()
    )


# What the loaded config holds in each overlaid field; a native answer that
# does not fit is refused rather than stored.
_OVERLAID_FIELD_VALID = {
    "mode": _is_one_of(frozenset(get_args(GuardMode))),
    "security_level": _is_one_of(VALID_SECURITY_LEVELS),
    "protection_posture": _is_one_of(VALID_PROTECTION_POSTURES),
    "protection_posture_explicit": _is_bool,
    "default_action": _is_action,
    "unknown_publisher_action": _is_action,
    "changed_hash_action": _is_action,
    "new_network_domain_action": _is_action,
    "subprocess_action": _is_action,
    "risk_actions": _is_risk_action_map,
    "harness_risk_actions": _is_harness_risk_action_maps,
    "telemetry": _is_bool,
    "sync": _is_bool,
    "receipt_redaction_level": _is_one_of(VALID_RECEIPT_REDACTION_LEVELS),
}


def _existing_legacy_guard_home(user_home: Path) -> Path | None:
    for relative_path in LEGACY_GUARD_DIRNAMES:
        candidate = user_home / relative_path
        if candidate.exists():
            return candidate
    return None
