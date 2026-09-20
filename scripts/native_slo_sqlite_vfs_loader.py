"""Bounded loader descriptor lifetime for SQLite's process-resident code images."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

MAX_LOADER_IMAGES = 16
_LOCK = threading.Lock()


class _LoadExtension(Protocol):
    """Signature admitted by the caller's existing Python 3.12 runtime guard."""

    def __call__(self, name: str, /, *, entrypoint: str | None = None) -> None: ...


@dataclass(frozen=True)
class _LoaderImage:
    descriptor: int
    identity: dict[str, Any]
    alias: str


_IMAGES: dict[tuple[int, int], _LoaderImage] = {}


def _key(identity: Mapping[str, Any]) -> tuple[int, int]:
    return identity["device"], identity["inode"]


def _require_descriptor_identity(descriptor: int, identity: Mapping[str, Any]) -> None:
    metadata = os.fstat(descriptor)
    actual = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "bytes": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or any(identity.get(name) != value for name, value in actual.items())
    ):
        raise ValueError("retained SQLite loader descriptor identity changed")


def load_verified_extension(connection: sqlite3.Connection, descriptor: int, identity: Mapping[str, Any]) -> None:
    """Keep an attempted dlopen pathname unique until its process exits.

    The caller's pinned context has verified the current digest and rechecks it
    at observer teardown. An attempted load may leave resident code even when
    it raises; those descriptors remain quarantined under the same fixed bound.
    """
    with _LOCK:
        _require_descriptor_identity(descriptor, identity)
        key = _key(identity)
        image = _IMAGES.get(key)
        if image is not None:
            if image.identity != identity:
                raise ValueError("a retained SQLite loader image changed after verification")
            _require_descriptor_identity(image.descriptor, identity)
        else:
            if len(_IMAGES) >= MAX_LOADER_IMAGES:
                raise ValueError("SQLite loader exceeds the sixteen-image descriptor bound")
            retained = os.dup(descriptor)
            try:
                os.set_inheritable(retained, False)
                _require_descriptor_identity(retained, identity)
                image = _LoaderImage(retained, dict(identity), f"/proc/self/fd/{retained}")
                # Nothing evicts or closes an alias once it may reach SQLite.
                _IMAGES[key] = image
            except BaseException:
                os.close(retained)
                raise
        load_extension = cast(_LoadExtension, connection.load_extension)
        load_extension(image.alias, entrypoint="sqlite3_guardvfsext_init")


def loader_descriptor_report(identity: Mapping[str, Any], *, admitted_images: int) -> dict[str, Any]:
    with _LOCK:
        selected = _IMAGES.get(_key(identity))
        retained = False
        if selected is not None:
            try:
                _require_descriptor_identity(selected.descriptor, identity)
                retained = not os.get_inheritable(selected.descriptor)
            except (OSError, ValueError):
                pass
        return {
            "scope": "process_resident_sqlite_extension_loader",
            "descriptor_lifetime": "process_exit",
            "maximum_retained_image_descriptors": MAX_LOADER_IMAGES,
            "retained_image_descriptors": len(_IMAGES),
            "admitted_image_descriptors": admitted_images,
            "unadmitted_image_descriptors": len(_IMAGES) - admitted_images,
            "selected_image_descriptor_retained": retained,
            "selected_descriptor_close_on_exec": retained,
            "database_and_vfs_descriptors_included": False,
        }
