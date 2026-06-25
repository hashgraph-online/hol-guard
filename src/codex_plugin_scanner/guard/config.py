"""Guard configuration loading and resolution."""

from __future__ import annotations

import importlib
import json
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tomllib
else:  # pragma: no cover - runtime compatibility
    tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

from .approval_gate import ApprovalGateGrant, public_config, require_settings_write
from .models import GuardAction, GuardMode

DEFAULT_GUARD_DIRNAME = ".hol-guard"
LEGACY_GUARD_DIRNAMES = (".config/.ai-plugin-scanner-guard", ".ai-plugin-scanner-guard", ".holguard")
NON_MIGRATED_GUARD_RUNTIME_FILES = frozenset(
    {
        "daemon-state.json",
        "guard.db-journal",
        "guard.db-shm",
        "guard.db-wal",
    }
)
GUARD_HOME_METADATA_FILES = frozenset(
    {
        "oauth-keychain-access.json",
        "system-keyring-availability.json",
    }
)
GUARD_DB_BACKUP_TIMEOUT_SECONDS = 5.0
GUARD_DB_BACKUP_SLEEP_SECONDS = 0.05
WORKSPACE_CONFIG_FILENAMES = (".ai-plugin-scanner-guard.toml", ".hol-guard.toml")
MAX_APPROVAL_WAIT_TIMEOUT_SECONDS = 600
VALID_GUARD_ACTIONS = {"allow", "warn", "review", "block", "sandbox-required", "require-reapproval"}
VALID_GUARD_MODES = {"observe", "prompt", "enforce"}
VALID_SECURITY_LEVELS = {"relaxed", "gentle", "balanced", "strict", "paranoid", "custom"}
VALID_RISK_ACTION_KEYS = {
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
}
DEFAULT_SECURITY_LEVEL = "balanced"
SECURITY_LEVEL_RISK_ACTIONS: dict[str, dict[str, GuardAction]] = {
    "relaxed": {
        "local_secret_read": "warn",
        "credential_exfiltration": "warn",
        "data_flow_exfiltration": "warn",
        "destructive_shell": "warn",
        "encoded_execution": "warn",
        "network_egress": "allow",
        "prompt_injection": "warn",
        "mcp_dangerous_tool": "warn",
        "malicious_skill": "warn",
        "package_script": "warn",
        "persistence": "warn",
        "guard_bypass": "warn",
        "cloud_advisory": "allow",
        "encoded_exfiltration": "warn",
    },
    "gentle": {
        "local_secret_read": "warn",
        "credential_exfiltration": "warn",
        "data_flow_exfiltration": "warn",
        "destructive_shell": "warn",
        "encoded_execution": "warn",
        "network_egress": "allow",
        "prompt_injection": "warn",
        "mcp_dangerous_tool": "warn",
        "malicious_skill": "warn",
        "package_script": "warn",
        "persistence": "warn",
        "guard_bypass": "warn",
        "cloud_advisory": "allow",
        "encoded_exfiltration": "warn",
    },
    "balanced": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "warn",
        "prompt_injection": "require-reapproval",
        "mcp_dangerous_tool": "require-reapproval",
        "malicious_skill": "require-reapproval",
        "package_script": "warn",
        "persistence": "require-reapproval",
        "guard_bypass": "block",
        "cloud_advisory": "warn",
        "encoded_exfiltration": "require-reapproval",
    },
    "strict": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "block",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "require-reapproval",
        "prompt_injection": "block",
        "mcp_dangerous_tool": "block",
        "malicious_skill": "block",
        "package_script": "require-reapproval",
        "persistence": "block",
        "guard_bypass": "block",
        "cloud_advisory": "require-reapproval",
        "encoded_exfiltration": "block",
    },
    "paranoid": {
        "local_secret_read": "block",
        "credential_exfiltration": "block",
        "data_flow_exfiltration": "block",
        "destructive_shell": "block",
        "encoded_execution": "block",
        "network_egress": "block",
        "prompt_injection": "block",
        "mcp_dangerous_tool": "block",
        "malicious_skill": "block",
        "package_script": "block",
        "persistence": "block",
        "guard_bypass": "block",
        "cloud_advisory": "block",
        "encoded_exfiltration": "block",
    },
    "custom": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "warn",
        "prompt_injection": "require-reapproval",
        "mcp_dangerous_tool": "require-reapproval",
        "malicious_skill": "require-reapproval",
        "package_script": "warn",
        "persistence": "require-reapproval",
        "guard_bypass": "block",
        "cloud_advisory": "warn",
        "encoded_exfiltration": "require-reapproval",
    },
}
EDITABLE_GUARD_SETTING_KEYS = frozenset(
    {
        "mode",
        "security_level",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "risk_actions",
        "harness_risk_actions",
        "approval_wait_timeout_seconds",
        "approval_surface_policy",
        "desktop_notifications",
        "telemetry",
        "sync",
        "billing",
        "receipt_redaction_level",
    }
)
VALID_APPROVAL_SURFACE_POLICIES = {"auto-open-once", "native-only", "approval-center"}
VALID_RECEIPT_REDACTION_LEVELS = frozenset({"full", "partial", "none"})
BARE_TOML_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
WORKSPACE_BLOCKED_POLICY_KEYS = frozenset(
    {
        "mode",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "security_level",
        "risk_actions",
        "harness_risk_actions",
        "harnesses",
        "publishers",
        "artifacts",
    }
)


class GuardHomeMigrationError(RuntimeError):
    """Raised when legacy Guard state cannot be migrated safely."""


def _coerce_action_map(payload: object) -> dict[str, GuardAction]:
    if not isinstance(payload, dict):
        return {}
    action_map: dict[str, GuardAction] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        action = (
            value
            if isinstance(value, str)
            else (value.get("action") or value.get("default_action"))
            if isinstance(value, dict)
            else None
        )
        resolved_action = _coerce_loaded_guard_action(action, None)
        if resolved_action is not None:
            action_map[key] = resolved_action
    return action_map


def _coerce_risk_action_map(payload: object) -> dict[str, GuardAction]:
    if not isinstance(payload, dict):
        return {}
    action_map: dict[str, GuardAction] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or key not in VALID_RISK_ACTION_KEYS:
            continue
        action = (
            value
            if isinstance(value, str)
            else (value.get("action") or value.get("default_action"))
            if isinstance(value, dict)
            else None
        )
        resolved_action = _coerce_loaded_guard_action(action, None)
        if resolved_action is not None:
            action_map[key] = resolved_action
    return action_map


def _coerce_harness_risk_action_map(payload: object) -> dict[str, dict[str, GuardAction]]:
    if not isinstance(payload, dict):
        return {}
    action_map: dict[str, dict[str, GuardAction]] = {}
    for harness, value in payload.items():
        if not isinstance(harness, str) or not harness.strip():
            continue
        harness_actions = _coerce_risk_action_map(value)
        if harness_actions:
            action_map[harness] = harness_actions
    return action_map


@dataclass(frozen=True, slots=True)
class GuardConfig:
    """Merged local Guard configuration."""

    guard_home: Path
    workspace: Path | None
    mode: GuardMode = "prompt"
    security_level: str = DEFAULT_SECURITY_LEVEL
    default_action: GuardAction = "warn"
    unknown_publisher_action: GuardAction = "review"
    changed_hash_action: GuardAction = "require-reapproval"
    new_network_domain_action: GuardAction = "warn"
    subprocess_action: GuardAction = "warn"
    approval_wait_timeout_seconds: int = 120
    approval_surface_policy: str = "auto-open-once"
    desktop_notifications: bool = True
    telemetry: bool = False
    sync: bool = False
    billing: bool = False
    runtime_detector_registry: bool = False
    runtime_detector_timeout_ms: int = 50
    runtime_detector_debug_trace: bool = False
    runtime_detector_disabled_ids: tuple[str, ...] = ()
    sandbox_analysis: str = "off"
    risk_actions: dict[str, GuardAction] | None = None
    harness_risk_actions: dict[str, dict[str, GuardAction]] | None = None
    harness_actions: dict[str, GuardAction] | None = None
    publisher_actions: dict[str, GuardAction] | None = None
    artifact_actions: dict[str, GuardAction] | None = None
    evidence_retain_days: int = 90
    receipt_redaction_level: str = "full"

    def resolve_action_override(
        self,
        harness: str,
        artifact_id: str | None,
        publisher: str | None,
    ) -> GuardAction | None:
        if artifact_id is not None and self.artifact_actions is not None and artifact_id in self.artifact_actions:
            return self.artifact_actions[artifact_id]
        if publisher is not None and self.publisher_actions is not None and publisher in self.publisher_actions:
            return self.publisher_actions[publisher]
        if self.harness_actions is not None and harness in self.harness_actions:
            return self.harness_actions[harness]
        return None


def resolve_guard_home(override: str | None = None) -> Path:
    """Resolve the Guard home directory."""

    if override:
        return Path(override).expanduser().resolve()
    canonical_home = Path.home() / DEFAULT_GUARD_DIRNAME
    legacy_home = _existing_legacy_guard_home()
    if legacy_home is None:
        return canonical_home
    if _guard_home_has_sync_credentials(canonical_home):
        return canonical_home
    if _guard_home_has_state(canonical_home):
        return canonical_home
    if _guard_home_has_sync_credentials(legacy_home) or _guard_home_has_state(legacy_home):
        try:
            _migrate_guard_home_transactionally(source=legacy_home, destination=canonical_home)
        except GuardHomeMigrationError:
            return legacy_home
        return canonical_home
    return canonical_home


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except OSError:
        return {}


def load_guard_config(guard_home: Path, workspace: Path | None = None) -> GuardConfig:
    """Load Guard config from home and workspace overrides."""

    guard_home.mkdir(parents=True, exist_ok=True)
    home_config = _read_toml(guard_home / "config.toml")
    workspace_config = _load_workspace_guard_config(workspace)

    merged = _merge_config_payload(home_config, workspace_config)
    return GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        mode=_coerce_loaded_guard_mode(merged.get("mode"), "prompt"),
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
        approval_surface_policy=str(merged.get("approval_surface_policy", "auto-open-once")),
        desktop_notifications=_coerce_loaded_bool(merged.get("desktop_notifications", True)),
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
        security_level=_coerce_loaded_security_level(merged.get("security_level", DEFAULT_SECURITY_LEVEL)),
        risk_actions=_coerce_risk_action_map(merged.get("risk_actions")),
        harness_risk_actions=_coerce_harness_risk_action_map(merged.get("harness_risk_actions")),
        receipt_redaction_level=_coerce_loaded_receipt_redaction_level(merged.get("receipt_redaction_level", "full")),
    )


def editable_guard_settings(config: GuardConfig) -> dict[str, object]:
    """Return Guard config values that are safe to edit from the local dashboard."""

    return {
        "mode": config.mode,
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
        "desktop_notifications": config.desktop_notifications,
        "telemetry": config.telemetry,
        "sync": config.sync,
        "billing": config.billing,
        "receipt_redaction_level": config.receipt_redaction_level,
        "approval_gate": public_config(config.guard_home).to_dict(),
    }


def update_guard_settings(
    guard_home: Path,
    payload: dict[str, object],
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> GuardConfig:
    """Persist safe local Guard settings to config.toml and return the updated config."""

    require_settings_write(guard_home, approval_gate_grant=approval_gate_grant)
    current = _read_toml(guard_home / "config.toml")
    current_config = load_guard_config(guard_home)
    next_payload = dict(current)
    switching_to_custom_without_overrides = (
        payload.get("security_level") == "custom"
        and "risk_actions" not in payload
        and "harness_risk_actions" not in payload
    )
    if switching_to_custom_without_overrides:
        next_payload["risk_actions"] = _effective_risk_actions(current_config)
    for key, value in payload.items():
        if key not in EDITABLE_GUARD_SETTING_KEYS:
            continue
        next_payload[key] = _coerce_editable_setting(key, value)
    if next_payload.get("sync") is True and next_payload.get("billing") is not True:
        raise ValueError("Cloud sync requires a paid team plan.")
    _write_guard_config(guard_home / "config.toml", next_payload)
    return load_guard_config(guard_home)


def reset_guard_settings(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> GuardConfig:
    """Reset editable local Guard settings while preserving non-dashboard config."""

    require_settings_write(guard_home, approval_gate_grant=approval_gate_grant)
    current = _read_toml(guard_home / "config.toml")
    next_payload = {key: value for key, value in current.items() if key not in EDITABLE_GUARD_SETTING_KEYS}
    _write_guard_config(guard_home / "config.toml", next_payload)
    return load_guard_config(guard_home)


def _coerce_editable_setting(key: str, value: object) -> object:
    if key == "mode":
        if isinstance(value, str) and value in VALID_GUARD_MODES:
            return value
        raise ValueError("Invalid Guard mode.")
    if key == "security_level":
        return _coerce_security_level(value)
    if key == "risk_actions":
        return _coerce_risk_action_payload(value)
    if key == "harness_risk_actions":
        return _coerce_harness_risk_action_payload(value)
    if key.endswith("_action"):
        if isinstance(value, str) and value in VALID_GUARD_ACTIONS:
            return value
        raise ValueError("Invalid Guard action.")
    if key == "approval_surface_policy":
        if isinstance(value, str) and value in VALID_APPROVAL_SURFACE_POLICIES:
            return value
        raise ValueError("Invalid approval surface policy.")
    if key == "approval_wait_timeout_seconds":
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_APPROVAL_WAIT_TIMEOUT_SECONDS:
            return value
        raise ValueError(f"Approval wait timeout must be between 0 and {MAX_APPROVAL_WAIT_TIMEOUT_SECONDS} seconds.")
    if key in {"desktop_notifications", "telemetry", "sync", "billing"}:
        if isinstance(value, bool):
            return value
        raise ValueError(f"{key} must be true or false.")
    if key == "receipt_redaction_level":
        if isinstance(value, str) and value in VALID_RECEIPT_REDACTION_LEVELS:
            return value
        raise ValueError("Invalid receipt redaction level. Must be 'full', 'partial', or 'none'.")
    raise ValueError(f"Unsupported Guard setting: {key}")


def _coerce_security_level(value: object) -> str:
    if isinstance(value, str) and value in VALID_SECURITY_LEVELS:
        return value
    raise ValueError("Invalid Guard security level.")


def _coerce_loaded_security_level(value: object) -> str:
    if isinstance(value, str) and value in VALID_SECURITY_LEVELS:
        return value
    return DEFAULT_SECURITY_LEVEL


def _coerce_loaded_guard_mode(value: object, fallback: GuardMode) -> GuardMode:
    if value == "observe":
        return "observe"
    if value == "prompt":
        return "prompt"
    if value == "enforce":
        return "enforce"
    return fallback


def _coerce_loaded_guard_action(value: object, fallback: GuardAction | None) -> GuardAction | None:
    if value == "allow":
        return "allow"
    if value == "warn":
        return "warn"
    if value == "review":
        return "review"
    if value == "block":
        return "block"
    if value == "sandbox-required":
        return "sandbox-required"
    if value == "require-reapproval":
        return "require-reapproval"
    return fallback


def _coerce_loaded_guard_action_or_default(value: object, fallback: GuardAction) -> GuardAction:
    resolved = _coerce_loaded_guard_action(value, None)
    return resolved if resolved is not None else fallback


def _coerce_loaded_bool(value: object) -> bool:
    return value if isinstance(value, bool) else False


def _coerce_loaded_non_negative_int(value: object, fallback: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return fallback


def _coerce_loaded_positive_int(value: object, fallback: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _coerce_loaded_string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


_VALID_SANDBOX_MODES = {"off", "suspicious", "strict"}


def _coerce_sandbox_analysis(value: object) -> str:
    if isinstance(value, str) and value in _VALID_SANDBOX_MODES:
        return value
    return "off"


def _coerce_loaded_receipt_redaction_level(value: object) -> str:
    if isinstance(value, str) and value in VALID_RECEIPT_REDACTION_LEVELS:
        return value
    return "full"


def _coerce_risk_action_payload(value: object) -> dict[str, GuardAction]:
    if not isinstance(value, dict):
        raise ValueError("Risk actions must be a table.")
    action_map: dict[str, GuardAction] = {}
    for key, action in value.items():
        if not isinstance(key, str) or key not in VALID_RISK_ACTION_KEYS:
            continue
        resolved_action = _coerce_loaded_guard_action(action, None)
        if resolved_action is not None:
            action_map[key] = resolved_action
    return action_map


def _coerce_harness_risk_action_payload(value: object) -> dict[str, dict[str, GuardAction]]:
    if not isinstance(value, dict):
        raise ValueError("Harness risk actions must be a table.")
    harness_actions: dict[str, dict[str, GuardAction]] = {}
    for harness, actions in value.items():
        if not isinstance(harness, str) or not harness.strip():
            continue
        harness_actions[harness] = _coerce_risk_action_payload(actions)
    return harness_actions


def _effective_risk_actions(config: GuardConfig) -> dict[str, GuardAction]:
    defaults = SECURITY_LEVEL_RISK_ACTIONS.get(
        config.security_level,
        SECURITY_LEVEL_RISK_ACTIONS[DEFAULT_SECURITY_LEVEL],
    )
    return {**defaults, **dict(config.risk_actions or {})}


def resolve_risk_action(config: GuardConfig, risk_class: str | None, *, harness: str | None) -> GuardAction | None:
    """Resolve the configured action for a concrete runtime risk class."""
    if risk_class is None:
        return None
    if harness is not None and config.harness_risk_actions:
        harness_map = config.harness_risk_actions.get(harness)
        if harness_map is not None and risk_class in harness_map:
            return harness_map[risk_class]
    if config.risk_actions and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    defaults = SECURITY_LEVEL_RISK_ACTIONS.get(
        config.security_level,
        SECURITY_LEVEL_RISK_ACTIONS[DEFAULT_SECURITY_LEVEL],
    )
    return defaults.get(risk_class)


def _write_guard_config(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = _toml_lines_for_table(payload, ())
    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def _toml_lines_for_table(payload: Mapping[str, object], path: tuple[str, ...]) -> list[str]:
    lines: list[str] = []
    for key, value in payload.items():
        if isinstance(value, Mapping):
            child_path = (*path, key)
            lines.append(f"[{'.'.join(child_path)}]")
            lines.extend(_toml_lines_for_table(value, child_path))
        else:
            lines.append(f"{_toml_key(key)} = {_toml_literal(value)}")
    return lines


def _toml_key(value: str) -> str:
    if BARE_TOML_KEY.match(value):
        return value
    return json.dumps(value)


def _toml_literal(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, tuple | list):
        return "[" + ", ".join(_toml_literal(item) for item in value) + "]"
    if isinstance(value, Mapping):
        return _toml_inline_table(value)
    return json.dumps(str(value))


def _toml_inline_table(value: Mapping[str, object]) -> str:
    items: list[str] = []
    for key, item in value.items():
        items.append(f"{_toml_key(key)} = {_toml_literal(item)}")
    return "{ " + ", ".join(items) + " }"


def overlay_synced_guard_policy(
    config: GuardConfig,
    payload: dict[str, object] | None,
) -> GuardConfig:
    if not isinstance(payload, dict):
        return config
    next_mode = config.mode
    raw_mode = payload.get("mode")
    if isinstance(raw_mode, str) and raw_mode in VALID_GUARD_MODES:
        next_mode = raw_mode
    default_action = _coerce_action_value(payload.get("defaultAction"), config.default_action)
    unknown_publisher_action = _coerce_action_value(
        payload.get("unknownPublisherAction"),
        config.unknown_publisher_action,
    )
    changed_hash_action = _coerce_action_value(
        payload.get("changedHashAction"),
        config.changed_hash_action,
    )
    new_network_domain_action = _coerce_action_value(
        payload.get("newNetworkDomainAction"),
        config.new_network_domain_action,
    )
    subprocess_action = _coerce_action_value(
        payload.get("subprocessAction"),
        config.subprocess_action,
    )
    sync_enabled = payload.get("syncEnabled")
    cloud_redaction_level = payload.get("receiptRedactionLevel")
    return replace(
        config,
        mode=next_mode,
        default_action=default_action,
        unknown_publisher_action=unknown_publisher_action,
        changed_hash_action=changed_hash_action,
        new_network_domain_action=new_network_domain_action,
        subprocess_action=subprocess_action,
        sync=bool(sync_enabled) if isinstance(sync_enabled, bool) else config.sync,
        receipt_redaction_level=(
            cloud_redaction_level
            if cloud_redaction_level in VALID_RECEIPT_REDACTION_LEVELS
            else config.receipt_redaction_level
        ),
    )


def _coerce_action_value(value: object, fallback: GuardAction) -> GuardAction:
    return _coerce_loaded_guard_action_or_default(value, fallback)


def _string_object_table(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return {key: item for key, item in value.items() if isinstance(key, str)}


def _existing_legacy_guard_home() -> Path | None:
    for relative_path in LEGACY_GUARD_DIRNAMES:
        candidate = Path.home() / relative_path
        if candidate.is_dir():
            return candidate
    return None


def _migrate_guard_home_state(*, source: Path, destination: Path) -> None:
    if not source.exists():
        return
    for entry in source.iterdir():
        if entry.name.startswith("."):
            continue
        target = destination / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, target)


def _migrate_guard_home_transactionally(*, source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="guard-home-migration-") as staging:
            staging_path = Path(staging)
            _migrate_guard_home_state(source=source, destination=staging_path)
            _copy_guard_database(source=source, destination=staging_path)
            _prune_retired_guard_db_sync_state(staging_path / "guard.db")
            _remove_guard_home_destination(destination)
            shutil.move(str(staging_path), str(destination))
    except OSError:
        raise GuardHomeMigrationError("guard home migration failed") from None


def _remove_guard_home_destination(path: Path) -> None:
    if not path.exists():
        return
    for entry in path.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    path.rmdir()


def _copy_guard_database(*, source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = source / "guard.db"
    if not source_db.is_file():
        return
    deadline = time.monotonic() + GUARD_DB_BACKUP_TIMEOUT_SECONDS
    backup_path = destination / "guard.db"
    while True:
        _raise_when_backup_deadline_elapsed(deadline)
        try:
            shutil.copy2(source_db, backup_path)
            break
        except OSError:
            time.sleep(GUARD_DB_BACKUP_SLEEP_SECONDS)
    try:
        with sqlite3.connect(backup_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.DatabaseError:
        backup_path.unlink(missing_ok=True)
        raise GuardHomeMigrationError("guard.db migration failed") from None


def _prune_retired_guard_db_sync_state(database_path: Path) -> None:
    try:
        with sqlite3.connect(database_path) as conn:
            conn.execute("DELETE FROM sync_payload WHERE key LIKE 'retired_%'")
    except sqlite3.DatabaseError:
        return


def _raise_when_backup_deadline_elapsed(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("guard.db migration timed out")


def _load_workspace_guard_config(workspace: Path | None) -> dict[str, object]:
    if workspace is None:
        return {}
    merged: dict[str, object] = {}
    for filename in WORKSPACE_CONFIG_FILENAMES:
        payload = _sanitize_workspace_guard_config(_read_toml(workspace / filename))
        merged.update(payload)
    return merged


def _sanitize_workspace_guard_config(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key not in WORKSPACE_BLOCKED_POLICY_KEYS}


def _merge_config_payload(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged_child = dict(merged[key])
            merged_child.update(value)
            merged[key] = merged_child
        else:
            merged[key] = value
    return merged


def _guard_home_has_state(path: Path) -> bool:
    if not path.exists():
        return False
    for entry in path.iterdir():
        if entry.name.startswith("."):
            continue
        if entry.is_dir():
            continue
        if entry.name in GUARD_HOME_METADATA_FILES:
            continue
        if entry.name == "guard.db":
            continue
        if entry.suffix in {".json", ".toml"}:
            continue
        return True
    db_path = path / "guard.db"
    if db_path.is_file():
        try:
            with sqlite3.connect(db_path) as conn:
                row = conn.execute("SELECT COUNT(*) FROM runtime_receipts").fetchone()
                if row is not None and row[0] > 0:
                    return True
        except sqlite3.DatabaseError:
            pass
    return False


def _guard_home_has_sync_credentials(path: Path) -> bool:
    database_path = path / "guard.db"
    if not database_path.is_file():
        return False
    try:
        with sqlite3.connect(database_path) as conn:
            row = conn.execute("SELECT value FROM sync_payload WHERE key = 'auth_context'").fetchone()
    except sqlite3.DatabaseError:
        return False
    return row is not None
