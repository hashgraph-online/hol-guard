"""Support helpers for the Pi harness adapter."""

from __future__ import annotations

import hashlib
import json
from glob import glob
from pathlib import Path

from ..models import GuardArtifact
from .pi_extension_source import managed_extension_source as managed_extension_source

PI_DIR = ".pi"
PI_AGENT_DIR = ".pi/agent"
OMP_DIR = ".omp"
OMP_AGENT_DIR = ".omp/agent"
PI_SETTINGS_FILE = "settings.json"
PI_MANAGED_EXTENSION_NAME = "hol-guard.ts"
EXTENSION_SUFFIXES = (".ts", ".js", ".mts", ".cts", ".mjs", ".cjs")
THEME_SUFFIXES = (".json", ".js", ".ts", ".yaml", ".yml")
REMOTE_RESOURCE_PREFIXES = ("npm:", "git:", "http://", "https://", "ssh://")


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def stable_suffix(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def artifact(
    *,
    artifact_id: str,
    name: str,
    artifact_type: str,
    scope: str,
    path: Path,
    metadata: dict[str, object] | None = None,
    publisher: str | None = None,
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name=name,
        harness="pi",
        artifact_type=artifact_type,
        source_scope=scope,
        config_path=str(path),
        publisher=publisher,
        metadata=metadata or {},
    )


def append_artifact(
    artifacts: list[GuardArtifact],
    seen_keys: set[str],
    next_artifact: GuardArtifact,
    *,
    dedupe_key: str,
) -> None:
    if dedupe_key in seen_keys:
        return
    seen_keys.add(dedupe_key)
    artifacts.append(next_artifact)


def is_remote_resource(value: str) -> bool:
    return value.startswith(REMOTE_RESOURCE_PREFIXES)


def resolve_configured_paths(settings_path: Path, value: str) -> tuple[Path, ...]:
    if is_remote_resource(value):
        return ()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = (settings_path.parent / candidate).expanduser()
    pattern = str(candidate)
    if any(char in pattern for char in "*?["):
        matches = [Path(item).expanduser().resolve() for item in glob(pattern, recursive=True)]
        return tuple(sorted(path for path in matches if path.exists()))
    resolved = candidate.resolve()
    return (resolved,) if resolved.exists() else ()


def enable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json_payload(settings_path) if settings_path.is_file() else {}
    raw_extensions = payload.get("extensions")
    extensions = [item for item in raw_extensions if isinstance(item, str)] if isinstance(raw_extensions, list) else []
    extension_value = str(extension_path)
    if extension_value not in extensions:
        extensions.append(extension_value)
    payload["extensions"] = extensions
    settings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def disable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    if not settings_path.is_file():
        return
    payload = json_payload(settings_path)
    raw_extensions = payload.get("extensions")
    if not isinstance(raw_extensions, list):
        return
    extension_value = str(extension_path)
    payload["extensions"] = [item for item in raw_extensions if isinstance(item, str) and item != extension_value]
    settings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
