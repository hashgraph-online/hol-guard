"""One private native esbuild image for contained Vitest transforms."""

from __future__ import annotations

import json
import os
import platform
import re
import stat
import sys
from pathlib import Path

from .restricted_node_test import _MAGIC
from .restricted_pytest_model import RestrictedPytestError
from .restricted_pytest_validation import _path_is_within

_LIMIT = 64 * 1024 * 1024


def _private_ancestor(path: Path) -> bool:
    """Whether a directory above `path` denies search to every other account.

    Package managers such as Bun can unpack images with mode 0777. Under a
    0700 home directory those bits grant nothing: no other account can
    traverse to the file, so it cannot replace it.
    """
    uid = os.getuid()
    for directory in path.parents:
        try:
            metadata = os.stat(directory, follow_symlinks=False)
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
        if metadata.st_uid == uid and not metadata.st_mode & (stat.S_IXGRP | stat.S_IXOTH):
            return True
    return False


def snapshot_esbuild(workspace: Path, private_root: Path) -> tuple[Path, Path, str] | None:
    manifest = workspace / "node_modules/esbuild/package.json"
    if not manifest.exists():
        return None
    try:
        resolved_manifest = manifest.resolve(strict=True)
        modules = workspace / "node_modules"
        if not _path_is_within(resolved_manifest, modules):
            raise ValueError("external manifest")
        descriptor = os.open(resolved_manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("nonregular manifest")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("oversized manifest")
        package = json.loads(raw)
        version = package.get("version")
        if (
            package.get("name") != "esbuild"
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}", version)
        ):
            raise ValueError("invalid manifest")
        system = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
        cpu = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine())
        if system is None or cpu is None:
            raise ValueError("unsupported platform")
        source = (modules / "@esbuild" / f"{system}-{cpu}" / "bin/esbuild").resolve(strict=True)
        if not _path_is_within(source, modules):
            raise ValueError("external image")
        # Another local account can replace a group- or world-writable image
        # before this copy. The private 0500 file is only as trustworthy as
        # the bytes read here, so those write bits stay a refusal unless a
        # private ancestor keeps every other account from reaching the file.
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or (metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not _private_ancestor(source))
                or not metadata.st_mode & stat.S_IXUSR
                or not 4 <= metadata.st_size <= _LIMIT
            ):
                raise ValueError("unsafe image")
            image = stream.read(_LIMIT + 1)
        if len(image) > _LIMIT or image[:4] not in _MAGIC:
            raise ValueError("not a native image")
        target = private_root / "esbuild"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(image)
        return source, target, version
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as error:
        raise RestrictedPytestError(
            "vitest_restricted_esbuild_unavailable", "The local transform image could not be safely prepared."
        ) from error
