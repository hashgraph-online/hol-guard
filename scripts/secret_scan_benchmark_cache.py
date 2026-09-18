"""Prepare and verify only generated fixture file data, never global caches."""

from __future__ import annotations

import ctypes
import mmap
import os
import sys
from pathlib import Path


def _resident_pages(fd: int, size: int) -> tuple[int, int]:
    if not size:
        return 0, 0
    libc = ctypes.CDLL(None, use_errno=True)
    mincore = libc.mincore
    mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)]
    mincore.restype = ctypes.c_int
    page_count = (size + mmap.PAGESIZE - 1) // mmap.PAGESIZE
    vector = (ctypes.c_ubyte * page_count)()
    with mmap.mmap(fd, size, access=mmap.ACCESS_COPY) as mapping:
        byte = ctypes.c_char.from_buffer(mapping)
        address = ctypes.addressof(byte)
        try:
            if mincore(address, size, vector) != 0:
                raise OSError(ctypes.get_errno(), "fixture cache residency query failed")
        finally:
            del byte
    return sum(bool(value & 1) for value in vector), page_count


def prepare_cache(root: Path, state: str) -> dict[str, int | str | bool]:
    """Fail explicitly if requested Linux file-data eviction cannot be proven.

    Even verified eviction leaves interpreter, executable, directory entries and
    other metadata caches uncontrolled. It is not a whole-machine cold start.
    """
    if state == "uncontrolled":
        return {"state": state, "verified": False}
    paths = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    file_bytes = 0
    if state == "prewarmed":
        for path in paths:
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    file_bytes += len(block)
        return {"state": "fixture-data-prewarmed", "verified": False, "files": len(paths), "bytes": file_bytes}
    if state != "evicted" or sys.platform != "linux" or not hasattr(os, "posix_fadvise"):
        raise RuntimeError("verified fixture-data eviction requires Linux fadvise and mincore")
    pages = 0
    resident = 0
    for path in paths:
        with path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            # DONTNEED may leave dirty pages resident; flush fixture writes first.
            os.fsync(stream.fileno())
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            current_resident, current_pages = _resident_pages(stream.fileno(), size)
            pages += current_pages
            resident += current_resident
            file_bytes += size
    if resident:
        raise RuntimeError("fixture-data eviction could not be verified; refusing a cold-cache label")
    return {
        "state": "fixture-file-data-evicted",
        "verified": True,
        "files": len(paths),
        "bytes": file_bytes,
        "pages": pages,
        "resident_pages": resident,
    }
