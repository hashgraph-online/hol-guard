"""Bind benchmark interpreters to the exact installed wheel contents."""

from __future__ import annotations

import hashlib
import importlib.metadata
import zipfile
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import BinaryIO

_PREFIX = "codex_plugin_scanner/"
_MAX_FILES = 20_000
_MAX_BYTES = 256 * 1024 * 1024


def _digest(names: Iterable[str], open_file: Callable[[str], AbstractContextManager[BinaryIO]]) -> str:
    selected = sorted(
        name
        for name in names
        if name.startswith(_PREFIX) and not name.endswith(("/", ".pyc")) and "/__pycache__/" not in name
    )
    if not selected or len(selected) > _MAX_FILES or len(selected) != len(set(selected)):
        raise ValueError("artifact package inventory invalid")
    total = 0
    result = hashlib.sha256()
    for name in selected:
        if ".." in Path(name).parts:
            raise ValueError("artifact package member invalid")
        digest = hashlib.sha256()
        with open_file(name) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total += len(chunk)
                if total > _MAX_BYTES:
                    raise ValueError("artifact package content exceeds bound")
                digest.update(chunk)
        result.update(name.encode("utf-8") + b"\0" + digest.digest())
    return result.hexdigest()


def installed_package_digest(distribution: importlib.metadata.Distribution) -> str:
    return _digest(
        (str(entry).replace("\\", "/") for entry in distribution.files or ()),
        lambda name: Path(distribution.locate_file(name)).open("rb"),
    )


def wheel_package_digest(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        return _digest(archive.namelist(), lambda name: archive.open(name))


def assert_installed_import_origin(distribution: importlib.metadata.Distribution) -> None:
    """Reject imports from another checkout even when wheel metadata is present."""
    import sys

    import codex_plugin_scanner

    root = Path(distribution.locate_file("codex_plugin_scanner")).resolve()
    expected = (root / "__init__.py").resolve()
    actual = Path(codex_plugin_scanner.__file__).resolve()
    if actual != expected or not actual.is_relative_to(root):
        raise RuntimeError("qualification imported code outside its installed wheel")
    for name, module in tuple(sys.modules.items()):
        if name.startswith("codex_plugin_scanner."):
            location = getattr(module, "__file__", None)
            if isinstance(location, str) and not Path(location).resolve().is_relative_to(root):
                raise RuntimeError("qualification mixed installed and checkout modules")
