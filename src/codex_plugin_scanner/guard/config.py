"""Guard configuration loading and resolution."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .models import GuardAction, GuardMode

DEFAULT_GUARD_DIRNAME = ".ai-plugin-scanner-guard"
VALID_GUARD_ACTIONS = {"allow", "warn", "review", "block", "sandbox-required", "require-reapproval"}
VALID_GUARD_MODES = {"observe", "prompt", "enforce"}


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


@dataclass(frozen=True, slots=True)
class GuardConfig:
    """Merged local Guard configuration."""

    guard_home: Path
    workspace: Path | None
    mode: GuardMode = "prompt"
    default_action: GuardAction = "warn"
    unknown_publisher_action: GuardAction = "review"
    changed_hash_action: GuardAction = "require-reapproval"
    new_network_domain_action: GuardAction = "warn"
    subprocess_action: GuardAction = "warn"
    approval_wait_timeout_seconds: int = 120
    telemetry: bool = False
    sync: bool = False
    billing: bool = False
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
    xdg_home = Path.home() / ".config" / DEFAULT_GUARD_DIRNAME
    legacy_home = Path.home() / DEFAULT_GUARD_DIRNAME
    return xdg_home if xdg_home.exists() else legacy_home


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
    workspace_config = _read_toml(workspace / ".ai-plugin-scanner-guard.toml") if workspace else {}

    merged: dict[str, object] = {**home_config, **workspace_config}
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
        telemetry=bool(merged.get("telemetry", False)),
        sync=bool(merged.get("sync", False)),
        billing=bool(merged.get("billing", False)),
        harness_actions=_coerce_action_map(merged.get("harnesses")),
        publisher_actions=_coerce_action_map(merged.get("publishers")),
        artifact_actions=_coerce_action_map(merged.get("artifacts")),
    )


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
