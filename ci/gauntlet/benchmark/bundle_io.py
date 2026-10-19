"""Bounded directory-only evidence reads; no symlinks or archive extraction."""

from __future__ import annotations

import os
import re
import stat
from pathlib import PurePosixPath

from .contracts import MAX_RECORD_BYTES, ContractError

MAX_FILES = 2048
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _path(name):
    if type(name) is not str or len(name) > 512 or not name.endswith(".json"):
        raise ContractError("bundle paths must be bounded relative JSON paths")
    parts = PurePosixPath(name).parts
    if not parts or len(parts) > 8 or any(not _SEGMENT.fullmatch(part) or part in {".", ".."} for part in parts):
        raise ContractError("unsafe/traversing bundle path")
    if str(PurePosixPath(name)) != name or "\\" in name:
        raise ContractError("bundle path is not canonical")
    return parts


def _tree(fd, prefix="", depth=0, budget=None):
    budget = [0] if budget is None else budget
    if depth > 8:
        raise ContractError("bundle directory exceeds depth limit")
    result = set()
    for entry in os.scandir(fd):
        budget[0] += 1
        if budget[0] > MAX_FILES * 2:
            raise ContractError("bundle exceeds directory-entry budget")
        name = prefix + entry.name
        if entry.is_symlink():
            raise ContractError("symlink bundle entry is forbidden")
        if entry.is_dir(follow_symlinks=False):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                result.update(_tree(child, name + "/", depth + 1, budget))
            finally:
                os.close(child)
        elif entry.is_file(follow_symlinks=False):
            _path(name)
            result.add(name)
        else:
            raise ContractError("nonregular bundle entry is forbidden")
        if len(result) > MAX_FILES:
            raise ContractError("bundle exceeds file-count budget")
    return result


def _read(fd, name):
    parts = _path(name)
    current = os.dup(fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        with os.fdopen(file_fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RECORD_BYTES:
                raise ContractError("nonregular or oversized bundle file")
            raw = handle.read(MAX_RECORD_BYTES + 1)
            if len(raw) > MAX_RECORD_BYTES:
                raise ContractError("bundle file exceeds byte budget")
            return raw
    finally:
        os.close(current)
