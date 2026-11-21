"""Test-only helpers: read and render Codex ``config.toml`` through the native runtime.

Guard's own code never parses or renders a Codex config in Python; the runtime's
``codex_toml_read`` and ``codex_toml_render`` kinds do. Tests use these to build
and inspect fixture configs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, datetime, time
from pathlib import Path

from codex_plugin_scanner.guard.codex_config import _Wire
from tests.python_oracles.codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE,
    CODEX_HOOK_INVENTORY_SOURCE_MALFORMED,
)

# Parsing and patching a large hand-written config is file-sized work.
_RENDER_TIMEOUT_SECONDS = 10.0


class TomlRefusedError(ValueError):
    """The runtime refused a TOML file as ``tomllib`` refuses it."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Codex config is not valid TOML: {reason}")
        self.reason = reason


def _meaning(meaning: object) -> object:
    """The value one runtime wire token stands for."""

    if not isinstance(meaning, dict):
        raise ValueError("Codex config read answer is malformed")
    kind, text = meaning.get("type"), meaning.get("value")
    if not isinstance(text, str):
        raise ValueError("Codex config read answer is malformed")
    if kind == "float":
        return float(text)
    if kind == "datetime":
        return datetime.fromisoformat(text)
    if kind == "date":
        return date.fromisoformat(text)
    if kind == "time":
        return time.fromisoformat(text)
    raise ValueError("Codex config read answer is malformed")


def _restore_native(value: object, tokens: Mapping[str, object]) -> object:
    if isinstance(value, str):
        return _meaning(tokens[value]) if value in tokens else value
    if isinstance(value, list):
        return [_restore_native(item, tokens) for item in value]
    if isinstance(value, dict):
        return {key: _restore_native(item, tokens) for key, item in value.items()}
    return value


def loads_toml(text: str) -> dict[str, object]:
    """``tomllib.loads``, answered by the runtime's ``codex_toml_read`` kind."""

    from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority

    answer = native_runner_authority("codex_toml_read", {"text": text}, timeout_seconds=_RENDER_TIMEOUT_SECONDS)
    error = answer.get("error")
    if isinstance(error, str):
        raise TomlRefusedError(error)
    payload, tokens = answer.get("payload"), answer.get("tokens")
    if not isinstance(payload, str) or not isinstance(tokens, dict):
        raise ValueError("Codex config read answer is malformed")
    restored = _restore_native(json.loads(payload), tokens)
    if not isinstance(restored, dict):
        raise ValueError("Codex config read answer is malformed")
    return restored


def read_toml_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        return loads_toml(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, TomlRefusedError):
        return {}


def read_config_bytes(path: Path) -> bytes | None:
    """The file as it stands, for rendering an edit back onto it."""

    try:
        return path.read_bytes()
    except OSError:
        return None


def dump_toml(payload: dict[str, object], *, original: str | bytes | None = None) -> str:
    """Render a Codex config payload, keeping the user's own file where we can.

    Guard reads `config.toml` into a plain dict and writes it back, so without
    `original` an install reflows the whole file: comments gone, keys and tables
    reordered, inline tables and arrays respelled. Codex users write that file by
    hand. Pass the text Guard read and the native ``codex_toml_render`` kind
    applies the edit to it instead, leaving every line Guard did not change
    exactly as it was, and checks the result still means the payload.
    """

    # Imported here rather than at module scope: the hook bridge imports this
    # module on every tool call and never renders a config.
    from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority

    if isinstance(original, bytes):
        try:
            original = original.decode("utf-8")
        except UnicodeDecodeError:
            original = None
    wire = _Wire(payload)
    answer = native_runner_authority(
        "codex_toml_render",
        {"payload": wire.text(payload), "tokens": wire.meanings, "original": original or None},
        timeout_seconds=_RENDER_TIMEOUT_SECONDS,
    )
    rendered = answer.get("text")
    if not isinstance(rendered, str):
        raise ValueError("Codex config render answer is malformed")
    return rendered


def parse_toml_object(data: bytes | None, *, path: Path, label: str) -> dict[str, object]:
    """Parse the captured TOML bytes without reopening the config path."""
    if data is None:
        return {}
    try:
        payload = loads_toml(data.decode("utf-8"))
    except (UnicodeDecodeError, TomlRefusedError) as exc:
        reason = (
            CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE
            if isinstance(exc, TomlRefusedError) and exc.reason == "duplicate_key"
            else CODEX_HOOK_INVENTORY_SOURCE_MALFORMED
        )
        raise RuntimeError(
            f"{reason}: Guard could not parse {label} at {path}. Repair the TOML before retrying install."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite non-object {label} at {path}."
        )
    return payload
