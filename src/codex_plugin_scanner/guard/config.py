"""Guard configuration loading and resolution."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

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
GUARD_DB_BACKUP_TIMEOUT_SECONDS = 5.0
GUARD_DB_BACKUP_SLEEP_SECONDS = 0.05
WORKSPACE_CONFIG_FILENAMES = (".ai-plugin-scanner-guard.toml", ".hol-guard.toml")
VALID_GUARD_ACTIONS = {"allow", "warn", "review", "block", "sandbox-required", "require-reapproval"}
VALID_GUARD_MODES = {"observe", "prompt", "enforce"}
VALID_SECURITY_LEVELS = {"balanced", "strict", "custom"}
VALID_RISK_ACTION_KEYS = {
    "local_secret_read",
    "credential_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
}
DEFAULT_SECURITY_LEVEL = "balanced"
SECURITY_LEVEL_RISK_ACTIONS: dict[str, dict[str, GuardAction]] = {
    "balanced": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "warn",
    },
    "strict": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "require-reapproval",
    },
    "custom": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "warn",
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
        "telemetry",
        "sync",
        "billing",
    }
)
VALID_APPROVAL_SURFACE_POLICIES = {"auto-open-once", "native-only", "approval-center"}
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
        if isinstance(action, str) and action in VALID_GUARD_ACTIONS:
            action_map[key] = action
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
        if isinstance(action, str) and action in VALID_GUARD_ACTIONS:
            action_map[key] = action
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
    telemetry: bool = False
    sync: bool = False
    billing: bool = False
    risk_actions: dict[str, GuardAction] | None = None
    harness_risk_actions: dict[str, dict[str, GuardAction]] | None = None
    harness_actions: dict[str, GuardAction] | None = None
    publisher_actions: dict[str, GuardAction] | None = None
    artifact_actions: dict[str, GuardAction] | None = None

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
        mode=str(merged.get("mode", "prompt")),  # type: ignore[arg-type]
        default_action=str(merged.get("default_action", "warn")),  # type: ignore[arg-type]
        unknown_publisher_action=str(merged.get("unknown_publisher_action", "review")),  # type: ignore[arg-type]
        changed_hash_action=str(merged.get("changed_hash_action", "require-reapproval")),  # type: ignore[arg-type]
        new_network_domain_action=str(merged.get("new_network_domain_action", "warn")),  # type: ignore[arg-type]
        subprocess_action=str(merged.get("subprocess_action", "warn")),  # type: ignore[arg-type]
        approval_wait_timeout_seconds=int(merged.get("approval_wait_timeout_seconds", 120)),
        approval_surface_policy=str(merged.get("approval_surface_policy", "auto-open-once")),
        telemetry=bool(merged.get("telemetry", False)),
        sync=bool(merged.get("sync", False)),
        billing=bool(merged.get("billing", False)),
        harness_actions=_coerce_action_map(merged.get("harnesses")),
        publisher_actions=_coerce_action_map(merged.get("publishers")),
        artifact_actions=_coerce_action_map(merged.get("artifacts")),
        security_level=_coerce_loaded_security_level(merged.get("security_level", DEFAULT_SECURITY_LEVEL)),
        risk_actions=_coerce_risk_action_map(merged.get("risk_actions")),
        harness_risk_actions=_coerce_harness_risk_action_map(merged.get("harness_risk_actions")),
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
        "telemetry": config.telemetry,
        "sync": config.sync,
        "billing": config.billing,
    }


def update_guard_settings(guard_home: Path, payload: dict[str, object]) -> GuardConfig:
    """Persist safe local Guard settings to config.toml and return the updated config."""

    current = _read_toml(guard_home / "config.toml")
    next_payload = dict(current)
    for key, value in payload.items():
        if key not in EDITABLE_GUARD_SETTING_KEYS:
            continue
        next_payload[key] = _coerce_editable_setting(key, value)
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
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 600:
            return value
        raise ValueError("Approval wait timeout must be between 0 and 600 seconds.")
    if key in {"telemetry", "sync", "billing"}:
        if isinstance(value, bool):
            return value
        raise ValueError(f"{key} must be true or false.")
    raise ValueError(f"Unsupported Guard setting: {key}")


def _coerce_security_level(value: object) -> str:
    if isinstance(value, str) and value in VALID_SECURITY_LEVELS:
        return value
    raise ValueError("Invalid Guard security level.")


def _coerce_loaded_security_level(value: object) -> str:
    if isinstance(value, str) and value in VALID_SECURITY_LEVELS:
        return value
    return DEFAULT_SECURITY_LEVEL


def _coerce_risk_action_payload(value: object) -> dict[str, GuardAction]:
    if not isinstance(value, dict):
        raise ValueError("Risk actions must be a table.")
    action_map: dict[str, GuardAction] = {}
    for key, action in value.items():
        if not isinstance(key, str) or key not in VALID_RISK_ACTION_KEYS:
            raise ValueError("Invalid Guard risk action.")
        if not isinstance(action, str) or action not in VALID_GUARD_ACTIONS:
            raise ValueError("Invalid Guard risk action.")
        action_map[key] = action
    return action_map


def _coerce_harness_risk_action_payload(value: object) -> dict[str, dict[str, GuardAction]]:
    if not isinstance(value, dict):
        raise ValueError("Harness risk actions must be a table.")
    harness_actions: dict[str, dict[str, GuardAction]] = {}
    for harness, risk_payload in value.items():
        if not isinstance(harness, str) or not harness.strip():
            raise ValueError("Invalid Guard harness.")
        harness_actions[harness] = _coerce_risk_action_payload(risk_payload)
    return harness_actions


def _effective_risk_actions(config: GuardConfig) -> dict[str, GuardAction]:
    defaults = SECURITY_LEVEL_RISK_ACTIONS.get(
        config.security_level, SECURITY_LEVEL_RISK_ACTIONS[DEFAULT_SECURITY_LEVEL]
    )
    return {**defaults, **dict(config.risk_actions or {})}


def resolve_risk_action(config: GuardConfig, risk_class: str | None, *, harness: str | None) -> GuardAction | None:
    """Resolve the configured action for a concrete runtime risk class."""

    if not isinstance(risk_class, str) or risk_class not in VALID_RISK_ACTION_KEYS:
        return None
    if isinstance(harness, str) and config.harness_risk_actions is not None:
        harness_actions = config.harness_risk_actions.get(harness)
        if harness_actions is not None and risk_class in harness_actions:
            return harness_actions[risk_class]
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    defaults = SECURITY_LEVEL_RISK_ACTIONS.get(
        config.security_level, SECURITY_LEVEL_RISK_ACTIONS[DEFAULT_SECURITY_LEVEL]
    )
    return defaults.get(risk_class)


def _write_guard_config(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = _toml_lines_for_table(payload, ())
    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def _toml_lines_for_table(payload: dict[object, object], path: tuple[str, ...]) -> list[str]:
    lines: list[str] = []
    scalar_items: list[tuple[str, object]] = []
    table_items: list[tuple[str, dict[object, object]]] = []
    for key, value in sorted(payload.items(), key=lambda item: str(item[0])):
        if not isinstance(key, str):
            continue
        if isinstance(value, dict):
            table_items.append((key, value))
            continue
        scalar_items.append((key, value))
    if path:
        lines.append(f"[{'.'.join(_toml_key(item) for item in path)}]")
    for key, value in scalar_items:
        lines.append(f"{_toml_key(key)} = {_toml_literal(value)}")
    for key, value in table_items:
        nested_lines = _toml_lines_for_table(value, (*path, key))
        if lines and nested_lines:
            lines.append("")
        lines.extend(nested_lines)
    return lines


def _toml_key(value: str) -> str:
    if BARE_TOML_KEY.match(value):
        return value
    return json.dumps(value)


def _toml_literal(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_literal(item) for item in value) + "]"
    if isinstance(value, dict):
        return _toml_inline_table(value)
    return json.dumps(str(value))


def _toml_inline_table(value: dict[object, object]) -> str:
    items: list[str] = []
    for key, item in sorted(value.items(), key=lambda entry: str(entry[0])):
        if isinstance(key, str):
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
    return replace(
        config,
        mode=next_mode,
        default_action=default_action,
        unknown_publisher_action=unknown_publisher_action,
        changed_hash_action=changed_hash_action,
        new_network_domain_action=new_network_domain_action,
        subprocess_action=subprocess_action,
        sync=bool(sync_enabled) if isinstance(sync_enabled, bool) else config.sync,
    )


def _coerce_action_value(value: object, fallback: GuardAction) -> GuardAction:
    if isinstance(value, str) and value in VALID_GUARD_ACTIONS:
        return value
    return fallback


def _existing_legacy_guard_home() -> Path | None:
    for relative_path in LEGACY_GUARD_DIRNAMES:
        candidate = Path.home() / relative_path
        if candidate.exists():
            return candidate
    return None


def _migrate_guard_home_state(*, source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.mkdir(parents=True, exist_ok=True)
    replace_database = not _guard_home_has_sync_credentials(destination) and not _guard_home_has_state(destination)
    for entry in source.iterdir():
        if entry.name in NON_MIGRATED_GUARD_RUNTIME_FILES:
            continue
        target = destination / entry.name
        if target.exists():
            if replace_database and entry.name == "secrets" and entry.is_dir() and target.is_dir():
                shutil.rmtree(target)
                shutil.copytree(entry, target)
                continue
            if entry.is_dir() and target.is_dir():
                _migrate_guard_home_state(source=entry, destination=target)
                continue
            if replace_database and entry.name == "guard.db" and entry.is_file():
                _copy_guard_database(source=entry, destination=target)
            continue
        if entry.is_dir():
            shutil.copytree(entry, target)
            continue
        if entry.name == "guard.db" and entry.is_file():
            _copy_guard_database(source=entry, destination=target)
            continue
        shutil.copy2(entry, target)


def _migrate_guard_home_transactionally(*, source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=destination.parent, prefix=f"{destination.name}-migration-") as temp_dir:
            staging_root = Path(temp_dir) / destination.name
            _migrate_guard_home_state(source=source, destination=staging_root)
            if destination.exists():
                _remove_guard_home_destination(destination)
            shutil.move(str(staging_root), str(destination))
    except OSError:
        raise GuardHomeMigrationError("guard home migration failed") from None


def _remove_guard_home_destination(path: Path) -> None:
    for entry in path.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
            continue
        entry.unlink()
    path.rmdir()


def _copy_guard_database(*, source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_destination = destination.with_name(f"{destination.name}.migrating")
    deadline = time.monotonic() + GUARD_DB_BACKUP_TIMEOUT_SECONDS
    try:
        with (
            sqlite3.connect(f"file:{source}?mode=ro", uri=True) as source_connection,
            sqlite3.connect(temporary_destination) as destination_connection,
        ):
            source_connection.backup(
                destination_connection,
                pages=128,
                progress=lambda *_: _raise_when_backup_deadline_elapsed(deadline),
                sleep=GUARD_DB_BACKUP_SLEEP_SECONDS,
            )
        temporary_destination.replace(destination)
    except (TimeoutError, sqlite3.Error):
        if temporary_destination.exists():
            temporary_destination.unlink()
        raise GuardHomeMigrationError("guard.db migration failed") from None


def _raise_when_backup_deadline_elapsed(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("guard.db migration timed out")


def _load_workspace_guard_config(workspace: Path | None) -> dict[str, object]:
    if workspace is None:
        return {}
    merged: dict[str, object] = {}
    for filename in WORKSPACE_CONFIG_FILENAMES:
        merged = _merge_config_payload(merged, _sanitize_workspace_guard_config(_read_toml(workspace / filename)))
    return merged


def _sanitize_workspace_guard_config(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key not in WORKSPACE_BLOCKED_POLICY_KEYS}


def _merge_config_payload(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            nested_existing = {name: nested_value for name, nested_value in existing.items() if isinstance(name, str)}
            nested_override = {name: nested_value for name, nested_value in value.items() if isinstance(name, str)}
            if "action" in nested_override or "default_action" in nested_override:
                nested_existing.pop("action", None)
                nested_existing.pop("default_action", None)
            merged[key] = _merge_config_payload(nested_existing, nested_override)
            continue
        merged[key] = value
    return merged


def _guard_home_has_state(path: Path) -> bool:
    if not path.exists():
        return False
    entries = list(path.iterdir())
    if not entries:
        return False
    if any(entry.name != "guard.db" for entry in entries):
        return True
    database_path = path / "guard.db"
    if not database_path.is_file():
        return True
    try:
        with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as connection:
            tables = {str(row[0]) for row in connection.execute("select name from sqlite_master where type = 'table'")}
            for table_name in (
                "harness_installations",
                "artifact_snapshots",
                "artifact_hashes",
                "artifact_diffs",
                "artifact_inventory",
                "policy_decisions",
                "runtime_receipts",
                "publisher_cache",
                "guard_events",
                "managed_installs",
                "guard_sessions",
                "guard_operations",
                "guard_operation_items",
                "guard_client_attachments",
                "guard_surface_opens",
                "approval_requests",
            ):
                if table_name not in tables:
                    continue
                if connection.execute(f"select 1 from {table_name} limit 1").fetchone() is not None:
                    return True
    except sqlite3.Error:
        return True
    return False


def _guard_home_has_sync_credentials(path: Path) -> bool:
    database_path = path / "guard.db"
    if not database_path.is_file():
        return False
    try:
        with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as connection:
            row = connection.execute("select 1 from sync_state where state_key = 'credentials' limit 1").fetchone()
    except sqlite3.Error:
        return False
    return row is not None
