"""Read Paseo configuration without persisting credentials or changing it."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from ..strict_json_pairs import unique_json_object
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
# Each native runtime's configuration-redirecting variables; the native
# classifier sees only these from the current environment.
_RUNTIME_ENV_PREFIXES = (
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_DISABLE_HOOKS",
    "CLAUDE_CODE_SIMPLE",
    "CODEX_HOME",
    "COPILOT_HOME",
    "COPILOT_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "OPENCODE_CONFIG",
    "OPENCODE_DISABLE",
    "PI_CODING_AGENT_DIR",
    "PI_CONFIG_DIR",
    "PI_PROFILE",
    "OMP_AGENT_DIR",
    "OMP_PROFILE",
)


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
    return unique_json_object(pairs, "Duplicate JSON keys are not supported in Paseo configuration.")


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


def paseo_providers(context: HarnessContext) -> tuple[PaseoProvider, ...]:
    """Classify every configured provider plus the supported native defaults in the native runtime."""
    answer = native_runner_authority(
        "paseo_providers",
        {
            "config_path": str(paseo_config_path(context)),
            "xdg_default": str(context.home_dir / ".config"),
            "environ": {
                key: value
                for key, value in os.environ.items()
                if value and key.upper().startswith(_RUNTIME_ENV_PREFIXES)
            },
        },
    )
    error = answer.get("error")
    if isinstance(error, str):
        raise ValueError(error)
    rows = answer.get("providers")
    if not isinstance(rows, list):
        raise NativeRunnerAuthorityError("Paseo providers are malformed")
    return tuple(_provider(row) for row in cast("list[object]", rows))


def _provider(row: object) -> PaseoProvider:
    if not isinstance(row, dict):
        raise NativeRunnerAuthorityError("Paseo providers are malformed")
    fields = cast("dict[str, object]", row)
    provider_id = fields.get("provider")
    native = fields.get("native_harness")
    enabled = fields.get("enabled")
    reason = fields.get("unsupported_reason")
    if (
        not isinstance(provider_id, str)
        or not (native is None or isinstance(native, str))
        or not isinstance(enabled, bool)
        or not (reason is None or isinstance(reason, str))
    ):
        raise NativeRunnerAuthorityError("Paseo providers are malformed")
    return PaseoProvider(provider_id, native, enabled, reason)
