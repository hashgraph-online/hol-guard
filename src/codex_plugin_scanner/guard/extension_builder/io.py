"""Bounded local input and canonical JSON. No network or executable discovery."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import cast

from .errors import BuilderError

MAX_INPUT_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 50_000
# Below CPython's minimum configurable conversion threshold, so decoding and
# canonical replay do not depend on a process-wide integer conversion setting.
MAX_INTEGER_DIGITS = 512


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2) + "\n"


def digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8"))


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def checked_path(path: Path, *, anchor: Path | None = None) -> Path:
    """Reject symlinks in every existing component without resolving through them.

    ``anchor`` names a root the installer or the operating system chose, not the
    caller: the frozen bundle's extraction directory, the directory the package
    was installed into, or the directory above the Guard home. Platforms put
    those roots behind symlinks we do not control -- macOS resolves the
    per-user ``TMPDIR`` through ``/var``, several Linux distributions symlink
    ``/tmp``, Fedora Silverblue reaches ``/home`` through a symlink to
    ``var/home``, and a Windows profile can sit behind a directory symlink
    (``mklink /D``) -- so refusing to read through the prefix refuses to read
    the program's own data files. A Windows junction (``mklink /J``) is not one
    of these cases: ``Path.is_symlink`` is measured False for a junction, so an
    ancestor walk passes through it unchanged.

    The anchor is resolved exactly once and every component strictly below it
    is still rejected when it is a symlink, which is the part an attacker who
    can write into the tree would have to plant.
    """

    absolute = path.absolute()
    if ".." in absolute.parts:
        raise BuilderError("unsafe_path", "Paths must not contain parent traversal.")
    if anchor is None:
        resolved = absolute
        components: tuple[Path, ...] = (*reversed(absolute.parents), absolute)
    else:
        base = anchor.absolute()
        if ".." in base.parts:
            raise BuilderError("unsafe_path", "Paths must not contain parent traversal.")
        try:
            relative = absolute.relative_to(base)
        except ValueError:
            raise BuilderError("unsafe_path", "Paths must stay inside their installation root.") from None
        try:
            root = Path(os.path.realpath(base))
        except OSError as exc:
            raise BuilderError("unsafe_path", "Cannot inspect an authoring path safely.") from exc
        resolved = root.joinpath(relative)
        components = tuple(root.joinpath(*relative.parts[:count]) for count in range(1, len(relative.parts) + 1))
    try:
        for item in components:
            if item.is_symlink():
                raise BuilderError("unsafe_path", "Symlink paths are not supported for authoring input or output.")
    except OSError as exc:
        raise BuilderError("unsafe_path", "Cannot inspect an authoring path safely.") from exc
    return resolved


def read_bytes(path: Path, *, limit: int = MAX_INPUT_BYTES, anchor: Path | None = None) -> bytes:
    """Read a bounded regular file; O_NONBLOCK prevents waiting on a substituted FIFO."""
    path = checked_path(path, anchor=anchor)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise BuilderError("input_file", "Input must be a regular file within the documented byte limit.")
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(content) > limit:
                raise BuilderError("input_limit", "Input exceeds the documented byte limit.")
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise BuilderError("input_changed", "Input changed during reading; retry with an immutable export.")
            return content
    except OSError as exc:
        raise BuilderError("input_file", "Cannot read the requested regular input file.") from exc


def text_from_bytes(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuilderError("input_encoding", "Input must be valid UTF-8.") from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuilderError("duplicate_json_key", "JSON input contains duplicate object keys.")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> object:
    raise BuilderError("invalid_json", "Nonfinite numbers are not valid authoring JSON.")


def _bounded_integer(value: str) -> int:
    if len(value.removeprefix("-")) > MAX_INTEGER_DIGITS:
        raise BuilderError("integer_limit", "JSON integers exceed the documented 512-digit limit.")
    return int(value)


def check_structure(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise BuilderError("structure_limit", "Input exceeds the documented structure budget.")
        if isinstance(item, float) and not math.isfinite(item):
            raise BuilderError("invalid_json", "Nonfinite numbers are not valid authoring JSON.")
        if isinstance(item, dict):
            entries = cast(dict[str, object], item)
            nodes += len(entries)
            if nodes > MAX_NODES:
                raise BuilderError("structure_limit", "Input exceeds the documented structure budget.")
            pending.extend((child, depth + 1) for child in entries.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in cast(list[object], item))


def parse_json(content: bytes) -> object:
    if len(content) > MAX_INPUT_BYTES:
        raise BuilderError("input_limit", "Input exceeds the documented byte limit.")
    try:
        value: object = json.loads(
            text_from_bytes(content),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_int=_bounded_integer,
        )
    except BuilderError:
        raise
    except (ValueError, RecursionError, OverflowError) as exc:
        raise BuilderError("invalid_json", "Input is not a supported bounded JSON document.") from exc
    check_structure(value)
    return value


def read_json(path: Path) -> object:
    return parse_json(read_bytes(path))


def object_value(value: object, *, code: str = "input_shape") -> dict[str, object]:
    if not isinstance(value, dict):
        raise BuilderError(code, "Expected a JSON object in the authoring document.")
    return cast(dict[str, object], value)


def list_value(value: object, *, maximum: int = 256) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise BuilderError("input_shape", "Expected a bounded JSON array in the authoring document.")
    return cast(list[object], value)
