"""Bounded build-object integrity checks and atomic immutable writes.

These helpers establish byte integrity only. Authenticated release authority
and native policy admission are separate requirements.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .object_native import addressed, objects_read

MAX_OBJECT_BYTES = 64 * 1024
MAX_BLOB_BYTES = 8 * 1024 * 1024


def digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def read_object(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_OBJECT_BYTES:
            raise ValueError("pack cache object type or length invalid")
        return stream.read(MAX_OBJECT_BYTES + 1)


def durable_directory(path: Path) -> None:
    if os.name != "posix":
        return  # Windows file fsync is FlushFileBuffers; directory handles differ.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def repair_link_count(directory: Path, path: Path, data: bytes) -> None:
    """Give an object a single link again after an interrupted publication.

    Publication links a complete temporary into place and removes the temporary
    afterwards, so a crash between those two steps leaves the object with two
    links. The runtime's bounded reader refuses a file whose link count is not
    one, which would make a complete, correct object unreadable. The bytes here
    already compared equal to the object on disk, so republishing them under a
    fresh inode repairs the link count without changing what the object holds.
    """
    if os.stat(path).st_nlink == 1:
        return
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".obj-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def publish_object(directory: Path, sha256: str, data: bytes) -> bool:
    """Return True for a new object; competing writers expose only complete files."""
    path = directory / f"{sha256}.json"
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".obj-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            try:
                os.link(temporary, path)
                durable_directory(directory)
                return True
            except FileExistsError:
                if path.is_symlink() or read_object(path) != data:
                    raise ValueError("existing pack cache object failed integrity") from None
                repair_link_count(directory, path, data)
                durable_directory(directory)
                return False
        finally:
            temporary.unlink(missing_ok=True)


def decode(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate pack object field")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("non-finite pack JSON value")

    return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)


def missing_object(directory: Path, sha256: str) -> FileNotFoundError:
    path = directory / f"{sha256}.json"
    return FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path))


class PackReader:
    def __init__(self, directory: Path):
        self.directory = directory
        self.reads = set()

    def blob(self, reference: dict[str, Any], depth: int = 0) -> bytes:
        # The runtime reads the cache directory and checks every object against
        # the length, digest and expansion its reference declares.
        reply = addressed(
            "expand",
            sources=objects_read(self.directory),
            mode="pack",
            directory=str(self.directory),
            reference=reference,
            depth=depth,
            invalid="invalid pack object reference",
        )
        if "need" in reply:
            raise missing_object(self.directory, reply["need"][0]["sha256"])
        self.reads.update(reply["reads"])
        return base64.b64decode(reply["data"], validate=True)

    def json(self, reference: dict[str, Any]):
        return decode(self.blob(reference))
