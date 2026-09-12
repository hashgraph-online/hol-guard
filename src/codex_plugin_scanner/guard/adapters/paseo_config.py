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
_COMMON_OVERRIDES = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "PATH",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
    }
)
_RUNTIME_OVERRIDES = {
    "claude-code": ("CLAUDE_CONFIG_DIR", "CLAUDE_CODE_DISABLE_HOOKS", "CLAUDE_CODE_SIMPLE"),
    "codex": ("CODEX_HOME",),
    "copilot": ("COPILOT_HOME", "COPILOT_CONFIG_DIR", "XDG_CONFIG_HOME"),
    "opencode": ("OPENCODE_CONFIG", "OPENCODE_DISABLE", "XDG_CONFIG_HOME"),
    "pi": ("PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "PI_PROFILE"),
    "omp": ("PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "PI_PROFILE", "OMP_AGENT_DIR", "OMP_PROFILE"),
}


@dataclass(frozen=True, slots=True)
class PaseoProvider:
    provider_id: str
    native_harness: str | None
    enabled: bool
    unsupported_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Expose provider identity and coverage limits without copying credentials."""
        return {
            "provider": self.provider_id,
            "native_harness": self.native_harness,
            "enabled": self.enabled,
            "unsupported_reason": self.unsupported_reason,
        }


def paseo_config_path(context: HarnessContext) -> Path:
    """Select the daemon home while respecting an explicitly supplied Guard home."""
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


def require_local_path(root: Path, path: Path, *, home_dir: Path | None = None) -> None:
    """Reject redirected ancestors and non-regular files before managed writes.

    A supplied user home is an explicit trust anchor and may itself be symlinked.
    Links below that home, including above a not-yet-created Guard root, are not.
    """
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError("Paseo managed path escapes its declared root.") from error
    anchor = Path(root.anchor)
    if home_dir is not None:
        home = Path(os.path.abspath(home_dir))
        if root.is_relative_to(home):
            anchor = home.resolve()
            root = anchor / root.relative_to(home)
            path = root / relative
    candidate = anchor
    for part in ("", *path.relative_to(anchor).parts):
        candidate = candidate / part if part else candidate
        if candidate.is_symlink():
            raise ValueError(f"Paseo refuses a symlink in a managed path: {candidate}")
        if candidate.exists():
            metadata = candidate.stat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError(f"Paseo requires regular managed files: {candidate}")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise ValueError(f"Paseo refuses a multiply-linked managed file: {candidate}")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Paseo managed path escapes its declared root.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys instead of silently accepting ambiguous provider settings."""
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
    """Read an optional object field without silently accepting malformed configuration."""
    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"Paseo {key} must be a JSON object.")
    return value


def _override_reason(harness: str, entry: dict[str, object], context: HarnessContext) -> str | None:
    """Identify execution overrides that can relocate or bypass native protection."""
    if "command" in entry:
        return "Custom provider commands require separate native Guard configuration and verification."
    environment: dict[str, str] = {}
    for key, value in _object_field(entry, "env").items():
        if not isinstance(value, str):
            raise ValueError("Paseo provider environment values must be strings.")
        environment[key] = value
    prefixes = (*_RUNTIME_OVERRIDES[harness], "HOL_GUARD_", "GUARD_")

    def redirects(key: str, value: str) -> bool:
        """Allow only the normal XDG home, never alternate native configuration roots."""
        if key.upper() == "XDG_CONFIG_HOME" and (
            not value or (Path(value).is_absolute() and Path(os.path.abspath(value)) == context.home_dir / ".config")
        ):
            return False
        return key.upper().startswith(prefixes)

    provider_keys = {str(key).upper() for key in environment}
    if provider_keys.intersection(_COMMON_OVERRIDES) or any(
        redirects(key, value) for key, value in environment.items()
    ):
        return "Provider environment overrides may relocate or disable native Guard protection."
    if any(
        value and key.upper().startswith(_RUNTIME_OVERRIDES[harness]) and redirects(key, value)
        for key, value in os.environ.items()
    ):
        return "The current environment redirects this runtime; verify the daemon's native configuration separately."
    return None


def _effective_provider_entry(raw: dict[str, object], base: object) -> dict[str, object]:
    """Merge the inherited native command and environment before classifying coverage."""
    if not isinstance(base, dict):
        raise ValueError("Paseo inherited provider configuration must be a JSON object.")
    return {**base, **raw, "env": {**_object_field(base, "env"), **_object_field(raw, "env")}}


def _provider(provider_id: str, raw: object, entries: dict[str, object], context: HarnessContext) -> PaseoProvider:
    """Classify a profile using its effective inherited command and environment."""
    if not _PROVIDER_ID.fullmatch(provider_id) or not isinstance(raw, dict):
        raise ValueError("Paseo providers must use valid provider IDs and JSON objects.")
    enabled = raw.get("enabled", provider_id != "omp")
    if not isinstance(enabled, bool):
        raise ValueError("Paseo provider enabled must be a boolean.")
    base = raw.get("extends", provider_id)
    native = PASEO_NATIVE_HARNESSES.get(base) if isinstance(base, str) else None
    reason = "ACP and plugin providers require a separately verified native Guard integration."
    if native is not None:
        inherited = entries.get(str(base), {}) if base != provider_id else {}
        effective = _effective_provider_entry(raw, inherited)
        if isinstance(inherited, dict) and "extends" in inherited:
            reason = "Nested provider inheritance requires separate native Guard verification."
        else:
            reason = _override_reason(native, effective, context)
    return PaseoProvider(provider_id, native, enabled, reason)


def paseo_providers(context: HarnessContext) -> tuple[PaseoProvider, ...]:
    """Read bounded provider configuration and include the supported native defaults."""
    payload = read_config_object(paseo_config_path(context))
    providers = _object_field(_object_field(payload, "agents"), "providers")
    if len(providers) > 256:
        raise ValueError("Paseo provider configuration exceeds the supported provider count.")
    entries: dict[str, object] = {key: {} for key in PASEO_NATIVE_HARNESSES}
    entries.update(providers)
    return tuple(_provider(key, value, entries, context) for key, value in sorted(entries.items()))
