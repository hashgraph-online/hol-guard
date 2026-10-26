"""Codex detection inputs read once and mapped back to the caller's path form.

The native detector inventories exactly the bytes the legacy-ownership
bindings were derived from, and returns paths the way the context spelled them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from ..codex_config import tomllib
from ..models import GuardArtifact
from ..native_path_anchor import anchor_to_process_directory


def read_source_bytes(path: Path) -> bytes | None:
    """File bytes, ``None`` when it is not a file, empty when it cannot be read.

    An unreadable file still counts as found and holds no hooks or servers,
    which is what an empty file means to the detector.
    """

    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return b""


def toml_payload_from_bytes(data: bytes | None) -> dict[str, object]:
    """``read_toml_payload`` over bytes already read: malformed TOML is empty."""

    if data is None:
        return {}
    try:
        payload = tomllib.loads(data.decode("utf-8"))
    except tomllib.TOMLDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def json_payload_from_bytes(data: bytes | None) -> dict[str, object]:
    """``_json_object`` over bytes already read: malformed JSON is empty."""

    if data is None:
        return {}
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def path_restorations(paths: tuple[Path, ...]) -> dict[str, str]:
    """Anchored (absolute) spelling to the spelling the context used."""

    restore: dict[str, str] = {}
    for path in paths:
        anchored = anchor_to_process_directory(path)
        if anchored != str(path):
            restore[anchored] = str(path)
    return restore


def _restore_value(restore: Mapping[str, str], value: object) -> object:
    if isinstance(value, str):
        return restore.get(value, value)
    if isinstance(value, list):
        return [_restore_value(restore, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_restore_value(restore, item) for item in value)
    if isinstance(value, dict):
        return {key: _restore_value(restore, item) for key, item in value.items()}
    return value


def restore_paths(
    restore: Mapping[str, str],
    artifacts: tuple[GuardArtifact, ...],
    found_paths: tuple[str, ...],
    warnings: tuple[str, ...],
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...], tuple[str, ...]]:
    """Return detection results with anchored source paths spelled as the caller did."""

    if not restore:
        return artifacts, found_paths, warnings

    def warning(text: str) -> str:
        for anchored, original in restore.items():
            text = text.replace(anchored, original)
        return text

    restored = tuple(
        replace(
            artifact,
            config_path=restore.get(artifact.config_path, artifact.config_path),
            metadata={key: _restore_value(restore, item) for key, item in artifact.metadata.items()},
        )
        for artifact in artifacts
    )
    return (
        restored,
        tuple(restore.get(path, path) for path in found_paths),
        tuple(warning(text) for text in warnings),
    )
