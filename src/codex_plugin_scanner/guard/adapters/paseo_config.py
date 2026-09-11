"""Read Paseo configuration without persisting credentials or changing it."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .base import HarnessContext

PASEO_NATIVE_HARNESSES = {
    "claude": "claude-code",
    "codex": "codex",
    "copilot": "copilot",
    "opencode": "opencode",
    "pi": "pi",
    "omp": "omp",
}
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_COMMON_OVERRIDES = frozenset({"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "PATH", "NODE_OPTIONS"})
_RUNTIME_OVERRIDES = {
    "claude-code": ("CLAUDE_CONFIG_DIR", "CLAUDE_CODE_DISABLE_HOOKS", "CLAUDE_CODE_SIMPLE"),
    "codex": ("CODEX_HOME",),
    "copilot": ("COPILOT_HOME", "COPILOT_CONFIG_DIR", "XDG_CONFIG_HOME"),
    "opencode": ("OPENCODE_CONFIG", "OPENCODE_DISABLE", "XDG_CONFIG_HOME"),
    "pi": ("PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "PI_PROFILE"),
    "omp": ("PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "PI_PROFILE", "OMP_AGENT_DIR", "OMP_PROFILE", "XDG_"),
}


@dataclass(frozen=True, slots=True)
class PaseoProvider:
    provider_id: str
    native_harness: str | None
    enabled: bool
    unsupported_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider_id,
            "native_harness": self.native_harness,
            "enabled": self.enabled,
            "unsupported_reason": self.unsupported_reason,
        }


def paseo_config_path(context: HarnessContext) -> Path:
    override = "" if context.home_override_explicit else os.environ.get("PASEO_HOME", "").strip()
    if not override:
        return context.home_dir / ".paseo" / "config.json"
    if override == "~" or override.startswith("~/"):
        root = context.home_dir / override[2:] if override != "~" else context.home_dir
    else:
        root = Path(override)
    if not root.is_absolute():
        raise ValueError("Use an absolute PASEO_HOME on the Paseo daemon host.")
    return root / "config.json"


def require_local_path(root: Path, path: Path) -> None:
    """Reject symlinks and non-regular leaves before managed native writes."""
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError as error:
        raise ValueError("Paseo managed path escapes its declared root.") from error
    candidate = root
    for part in ("", *relative.parts):
        candidate = candidate / part if part else candidate
        if candidate.is_symlink():
            raise ValueError(f"Paseo refuses a symlink in a managed path: {candidate}")
        if candidate.exists():
            metadata = candidate.stat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError(f"Paseo requires regular managed files: {candidate}")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise ValueError(f"Paseo refuses a multiply-linked managed file: {candidate}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not supported in Paseo configuration.")
        result[key] = value
    return result


def read_config_object(path: Path) -> dict[str, object]:
    """Bounded, no-follow read; malformed content is never treated as empty."""
    if not path.exists() and not path.is_symlink():
        return {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        if path.is_symlink():
            raise ValueError("Symlinked configuration is not supported.")
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CONFIG_BYTES:
                raise ValueError("Configuration must be a bounded regular file.")
            content = source.read(_MAX_CONFIG_BYTES + 1)
        if len(content) > _MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds the size limit.")
        payload = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(payload, dict):
            raise ValueError("Configuration must be a JSON object.")
        return payload
    except (OSError, UnicodeError, ValueError) as error:
        # Never include JSON snippets or environment values in diagnostics.
        raise ValueError(
            f"Cannot safely read configuration at {path}; repair it before installing Paseo protection."
        ) from error


def _object_field(payload: dict[str, object], key: str) -> dict[str, object]:
    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"Paseo {key} must be a JSON object.")
    return value


def _override_reason(harness: str, entry: dict[str, object]) -> str | None:
    if "command" in entry:
        return "Custom provider commands require separate native Guard configuration and verification."
    environment = _object_field(entry, "env")
    if any(not isinstance(value, str) for value in environment.values()):
        raise ValueError("Paseo provider environment values must be strings.")
    prefixes = (*_RUNTIME_OVERRIDES[harness], "HOL_GUARD_", "GUARD_")
    provider_keys = {str(key).upper() for key in environment}
    if provider_keys.intersection(_COMMON_OVERRIDES) or any(key.startswith(prefixes) for key in provider_keys):
        return "Provider environment overrides may relocate or disable native Guard protection."
    if any(value and key.upper().startswith(_RUNTIME_OVERRIDES[harness]) for key, value in os.environ.items()):
        return "The current environment redirects this runtime; verify the daemon's native configuration separately."
    return None


def _provider(provider_id: str, raw: object) -> PaseoProvider:
    if not _PROVIDER_ID.fullmatch(provider_id) or not isinstance(raw, dict):
        raise ValueError("Paseo providers must use valid provider IDs and JSON objects.")
    enabled = raw.get("enabled", provider_id != "omp")
    if not isinstance(enabled, bool):
        raise ValueError("Paseo provider enabled must be a boolean.")
    base = raw.get("extends", provider_id)
    native = PASEO_NATIVE_HARNESSES.get(base) if isinstance(base, str) else None
    reason = (
        _override_reason(native, raw)
        if native is not None
        else "ACP and plugin providers require a separately verified native Guard integration."
    )
    return PaseoProvider(provider_id, native, enabled, reason)


def paseo_providers(context: HarnessContext) -> tuple[PaseoProvider, ...]:
    payload = read_config_object(paseo_config_path(context))
    providers = _object_field(_object_field(payload, "agents"), "providers")
    if len(providers) > 256:
        raise ValueError("Paseo provider configuration exceeds the supported provider count.")
    entries: dict[str, object] = {key: {} for key in PASEO_NATIVE_HARNESSES}
    entries.update(providers)
    return tuple(_provider(key, value) for key, value in sorted(entries.items()))
