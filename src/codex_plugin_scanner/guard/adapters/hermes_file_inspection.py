"""Bounded previews, complete hashes, and fail-closed Hermes config parsing."""

from __future__ import annotations

import codecs
import hashlib
import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml  # type: ignore[import-untyped]

from ..windows_paths import open_windows_locked_regular_descriptor

HERMES_PREVIEW_BYTES = 64 * 1024
HERMES_CONFIG_MAX_BYTES = 2 * 1024 * 1024
HERMES_CONFIG_MAX_DEPTH = 32
HERMES_CONFIG_MAX_NODES = 20_000
HERMES_CONFIG_MAX_ALIASES = 0
_HASH_CHUNK_BYTES = 64 * 1024

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


class _HermesConfigLimitError(ValueError):
    def __init__(self, reason: HermesConfigInspectionReason) -> None:
        super().__init__(reason)
        self.reason: HermesConfigInspectionReason = reason


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

    logical_path = Path(path)
    try:
        before = os.lstat(logical_path)
    except FileNotFoundError:
        return _file_failure("file_missing")
    except OSError:
        return _file_failure("file_unreadable")
    if stat.S_ISLNK(before.st_mode):
        return _file_failure("file_symlink_unsupported", size_bytes=before.st_size)
    if not stat.S_ISREG(before.st_mode):
        return _file_failure("file_not_regular", size_bytes=before.st_size)
    if scope_root is not None and not _resolves_within(logical_path, scope_root):
        return _file_failure("file_symlink_escape", size_bytes=before.st_size)

    try:
        descriptor = (
            open_windows_locked_regular_descriptor(logical_path)
            if os.name == "nt"
            else os.open(
                logical_path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        )
    except FileNotFoundError:
        return _file_failure("file_changed_during_read", size_bytes=before.st_size)
    except OSError:
        return _file_failure("file_unreadable", size_bytes=before.st_size)

    preview = bytearray()
    retained = bytearray()
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    total = 0
    invalid_utf8 = False
    changed = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_key(opened) != _stat_key(before):
            changed = True
        while not changed:
            try:
                chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
            except OSError:
                return _file_failure("file_unreadable", size_bytes=total)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if len(preview) < HERMES_PREVIEW_BYTES:
                preview.extend(chunk[: HERMES_PREVIEW_BYTES - len(preview)])
            if content_limit_bytes is not None and len(retained) < content_limit_bytes:
                # Keep the parse buffer at the exact configured ceiling even
                # when the final read chunk crosses it.  The full stream is
                # still decoded and hashed before oversized input fails.
                retained.extend(chunk[: content_limit_bytes - len(retained)])
            try:
                decoder.decode(chunk, final=False)
            except UnicodeDecodeError:
                invalid_utf8 = True
        if not invalid_utf8 and not changed:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                invalid_utf8 = True
        final_opened = os.fstat(descriptor)
        if total != opened.st_size or _stat_key(final_opened) != _stat_key(opened):
            changed = True
    finally:
        os.close(descriptor)

    try:
        after = os.lstat(logical_path)
    except OSError:
        changed = True
    else:
        if _stat_key(after) != _stat_key(before):
            changed = True
    preview_text = bytes(preview).decode("utf-8", errors="ignore")
    truncated = total > len(preview)
    if changed:
        return _file_failure(
            "file_changed_during_read",
            preview=preview_text,
            size_bytes=total,
            analysis_truncated=truncated,
        )

    content_hash = f"sha256:{digest.hexdigest()}"
    if invalid_utf8:
        return HermesFileInspection(
            preview=preview_text,
            content=None,
            content_hash=content_hash,
            size_bytes=total,
            readable=True,
            complete=False,
            analysis_truncated=truncated,
            reason="file_invalid_utf8",
        )
    if content_limit_bytes is not None and total > content_limit_bytes:
        return HermesFileInspection(
            preview=preview_text,
            content=None,
            content_hash=content_hash,
            size_bytes=total,
            readable=True,
            complete=False,
            analysis_truncated=truncated,
            reason="file_too_large",
        )
    full_content = bytes(retained).decode("utf-8") if content_limit_bytes is not None else None
    return HermesFileInspection(
        preview=preview_text,
        content=full_content,
        content_hash=content_hash,
        size_bytes=total,
        readable=True,
        complete=True,
        analysis_truncated=truncated,
        reason=None,
    )


def inspect_hermes_config(path: Path, *, syntax: Literal["json", "yaml"]) -> HermesConfigInspection:
    """Parse a complete bounded config without accepting a prefix."""

    file = inspect_hermes_text_file(path, content_limit_bytes=HERMES_CONFIG_MAX_BYTES)
    if not file.complete or file.content is None:
        return HermesConfigInspection(file=file, payload=None, complete=False, reason=file.reason)
    try:
        if syntax == "json":
            parsed = json.loads(file.content, object_pairs_hook=_unique_json_mapping)
        else:
            parsed = _load_yaml(file.content)
        _validate_config_value(parsed)
    except _HermesConfigLimitError as exc:
        return HermesConfigInspection(file=file, payload=None, complete=False, reason=exc.reason)
    except (TypeError, ValueError, json.JSONDecodeError):
        return HermesConfigInspection(file=file, payload=None, complete=False, reason="config_parse_error")
    if parsed is None and syntax == "yaml":
        parsed = {}
    if not isinstance(parsed, dict):
        return HermesConfigInspection(file=file, payload=None, complete=False, reason="config_not_mapping")
    return HermesConfigInspection(file=file, payload=parsed, complete=True, reason=None)


def parse_hermes_yaml_mapping(content: str) -> dict[str, object] | None:
    """Safely parse bounded in-memory YAML used for skill frontmatter."""

    if len(content.encode("utf-8")) > HERMES_PREVIEW_BYTES:
        return None
    try:
        parsed = _load_yaml(content)
        _validate_config_value(parsed)
    except (TypeError, ValueError, _HermesConfigLimitError):
        return None
    return parsed if isinstance(parsed, dict) else None


def file_inspection_metadata(inspection: HermesFileInspection) -> dict[str, object]:
    """Return non-content metadata suitable for artifact identity and UI."""

    metadata: dict[str, object] = {
        "analysis_truncated": inspection.analysis_truncated,
        "inspection_complete": inspection.complete,
        "inspection_readable": inspection.readable,
        "preview_bytes": len(inspection.preview.encode("utf-8")),
        "size_bytes": inspection.size_bytes,
    }
    if inspection.content_hash is not None:
        metadata["content_hash"] = inspection.content_hash
    if inspection.reason is not None:
        metadata["inspection_reason"] = inspection.reason
    return metadata


def _load_yaml(content: str) -> object:
    alias_count = 0
    depth = 0
    nodes = 0
    try:
        for event in yaml.parse(content, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.events.AliasEvent):
                alias_count += 1
                if alias_count > HERMES_CONFIG_MAX_ALIASES:
                    raise _HermesConfigLimitError("config_alias_limit_exceeded")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                nodes += 1
                if depth > HERMES_CONFIG_MAX_DEPTH:
                    raise _HermesConfigLimitError("config_depth_limit_exceeded")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            elif isinstance(event, yaml.events.ScalarEvent):
                nodes += 1
            if nodes > HERMES_CONFIG_MAX_NODES:
                raise _HermesConfigLimitError("config_node_limit_exceeded")
        return yaml.load(content, Loader=_UniqueKeySafeLoader)
    except _HermesConfigLimitError:
        raise
    except yaml.YAMLError as exc:
        raise ValueError("invalid Hermes YAML") from exc


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(loader: object, node: object, deep: bool = False) -> dict[object, object]:
    if not isinstance(loader, yaml.SafeLoader) or not isinstance(node, yaml.nodes.MappingNode):
        raise ValueError("invalid YAML mapping")
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise _HermesConfigLimitError("config_value_invalid") from exc
        if duplicate:
            raise _HermesConfigLimitError("config_duplicate_key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for key, value in pairs:
        if key in mapping:
            raise _HermesConfigLimitError("config_duplicate_key")
        mapping[key] = value
    return mapping


def _validate_config_value(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > HERMES_CONFIG_MAX_NODES:
            raise _HermesConfigLimitError("config_node_limit_exceeded")
        if depth > HERMES_CONFIG_MAX_DEPTH:
            raise _HermesConfigLimitError("config_depth_limit_exceeded")
        if isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise _HermesConfigLimitError("config_value_invalid")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif (isinstance(current, float) and not math.isfinite(current)) or (
            current is not None and not isinstance(current, (str, int, float, bool))
        ):
            raise _HermesConfigLimitError("config_value_invalid")


def _file_failure(
    reason: HermesFileInspectionReason,
    *,
    preview: str = "",
    size_bytes: int = 0,
    analysis_truncated: bool = False,
) -> HermesFileInspection:
    return HermesFileInspection(
        preview=preview,
        content=None,
        content_hash=None,
        size_bytes=size_bytes,
        readable=False,
        complete=False,
        analysis_truncated=analysis_truncated,
        reason=reason,
    )


def _resolves_within(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        _ = resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _stat_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
        int(getattr(metadata, "st_file_attributes", 0)),
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
    "file_inspection_metadata",
    "inspect_hermes_config",
    "inspect_hermes_text_file",
    "parse_hermes_yaml_mapping",
]
