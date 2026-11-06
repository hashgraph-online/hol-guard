"""Bounded previews, complete hashes, and fail-closed Hermes config parsing.

The native runtime's `hermes-file-inspect` command does the race-checked read
and the PyYAML-compatible parse; this module only frames the request and
validates the answer. Without a compatible runtime every inspection is an
explicit `file_unreadable` failure, so callers refuse rather than guess.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from ..mdm.runtime_request import runtime_answer

HERMES_PREVIEW_BYTES = 64 * 1024
HERMES_CONFIG_MAX_BYTES = 2 * 1024 * 1024
HERMES_CONFIG_MAX_DEPTH = 32
HERMES_CONFIG_MAX_NODES = 20_000
HERMES_CONFIG_MAX_ALIASES = 0
_FEATURE = "native-hermes-file-inspect-v1"
_COMMAND = "hermes-file-inspect"
_SCHEMA = "hermes-file-inspect.v1"
# Complete content can escape to six bytes per input byte.
_OUTPUT_LIMIT = 32 * 1024 * 1024
_TIMEOUT_SECONDS = 30.0

HermesFileInspectionReason = Literal[
    "file_missing",
    "file_not_regular",
    "file_symlink_unsupported",
    "file_symlink_escape",
    "file_unreadable",
    "file_invalid_utf8",
    "file_too_large",
    "file_changed_during_read",
]
HermesConfigInspectionReason = (
    HermesFileInspectionReason
    | Literal[
        "config_parser_unavailable",
        "config_parse_error",
        "config_duplicate_key",
        "config_alias_limit_exceeded",
        "config_depth_limit_exceeded",
        "config_node_limit_exceeded",
        "config_not_mapping",
        "config_value_invalid",
    ]
)


@dataclass(frozen=True, slots=True)
class HermesFileInspection:
    """One complete byte identity plus a separately bounded UTF-8 preview."""

    preview: str
    content: str | None
    content_hash: str | None
    size_bytes: int
    readable: bool
    complete: bool
    analysis_truncated: bool
    reason: HermesFileInspectionReason | None


@dataclass(frozen=True, slots=True)
class HermesConfigInspection:
    """A complete, bounded config mapping or an explicit failure."""

    file: HermesFileInspection
    payload: dict[str, object] | None
    complete: bool
    reason: HermesConfigInspectionReason | None


def inspect_hermes_text_file(
    path: Path,
    *,
    scope_root: Path | None = None,
    content_limit_bytes: int | None = None,
) -> HermesFileInspection:
    """Stream a regular file once, hashing all bytes while retaining a preview.

    ``content_limit_bytes`` controls whether complete text is retained for a
    parser. It never limits hashing: oversized inputs are still streamed to a
    complete digest, but are marked incomplete for parsing.
    """

    request: dict[str, object] = {"op": "text", "path": os.path.abspath(path)}
    if scope_root is not None:
        request["scope_root"] = os.path.abspath(scope_root)
    if content_limit_bytes is not None:
        request["content_limit_bytes"] = content_limit_bytes
    answer = _answer(request)
    file = _file(answer.get("file")) if answer is not None else None
    return file if file is not None else _unavailable()


def inspect_hermes_config(path: Path, *, syntax: Literal["json", "yaml"]) -> HermesConfigInspection:
    """Parse a complete bounded config without accepting a prefix."""

    answer = _answer({"op": "config", "path": os.path.abspath(path), "syntax": syntax})
    inspection = _config(answer) if answer is not None else None
    if inspection is None:
        file = _unavailable()
        return HermesConfigInspection(file=file, payload=None, complete=False, reason=file.reason)
    return inspection


def _answer(request: dict[str, object]) -> dict[str, object] | None:
    return runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, **request},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


def _file(value: object) -> HermesFileInspection | None:
    if not isinstance(value, dict):
        return None
    fields = cast("dict[str, object]", value)
    preview = fields.get("preview")
    content = fields.get("content")
    content_hash = fields.get("content_hash")
    size_bytes = fields.get("size_bytes")
    readable = fields.get("readable")
    complete = fields.get("complete")
    truncated = fields.get("analysis_truncated")
    reason = fields.get("reason")
    if (
        not isinstance(preview, str)
        or not (content is None or isinstance(content, str))
        or not (content_hash is None or isinstance(content_hash, str))
        or not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes < 0
        or not isinstance(readable, bool)
        or not isinstance(complete, bool)
        or not isinstance(truncated, bool)
        or not (reason is None or isinstance(reason, str))
        or complete != (reason is None)
    ):
        return None
    return HermesFileInspection(
        preview=preview,
        content=content,
        content_hash=content_hash,
        size_bytes=size_bytes,
        readable=readable,
        complete=complete,
        analysis_truncated=truncated,
        reason=cast("HermesFileInspectionReason | None", reason),
    )


def _config(answer: dict[str, object]) -> HermesConfigInspection | None:
    file = _file(answer.get("file"))
    payload = answer.get("payload")
    complete = answer.get("complete")
    reason = answer.get("reason")
    if (
        file is None
        or not (payload is None or isinstance(payload, dict))
        or not isinstance(complete, bool)
        or not (reason is None or isinstance(reason, str))
        or complete != (reason is None)
        or complete != (payload is not None)
    ):
        return None
    return HermesConfigInspection(
        file=file,
        payload=cast("dict[str, object] | None", payload),
        complete=complete,
        reason=cast("HermesConfigInspectionReason | None", reason),
    )


def _unavailable() -> HermesFileInspection:
    return HermesFileInspection(
        preview="",
        content=None,
        content_hash=None,
        size_bytes=0,
        readable=False,
        complete=False,
        analysis_truncated=False,
        reason="file_unreadable",
    )


__all__ = [
    "HERMES_CONFIG_MAX_ALIASES",
    "HERMES_CONFIG_MAX_BYTES",
    "HERMES_CONFIG_MAX_DEPTH",
    "HERMES_CONFIG_MAX_NODES",
    "HERMES_PREVIEW_BYTES",
    "HermesConfigInspection",
    "HermesConfigInspectionReason",
    "HermesFileInspection",
    "HermesFileInspectionReason",
    "inspect_hermes_config",
    "inspect_hermes_text_file",
]
