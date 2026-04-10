"""Guard configuration loading and resolution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .models import GuardAction, GuardMode

DEFAULT_GUARD_DIRNAME = ".ai-plugin-scanner-guard"


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
    telemetry: bool = False
    sync: bool = False
    billing: bool = False


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
        telemetry=bool(merged.get("telemetry", False)),
        sync=bool(merged.get("sync", False)),
        billing=bool(merged.get("billing", False)),
    )
