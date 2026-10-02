"""Trusted namespace setup: noexec mounts and sealed mapping exceptions.

This module must be imported before remounting and before repository code. Its
temporary mount capabilities belong only to the already-isolated namespace.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import stat
from pathlib import Path

_MAX_FILE = 256 * 1024 * 1024
_MAX_TOTAL = 1024 * 1024 * 1024
_MAX_RECORDS = 1024
_MAX_TARGETS = 4096
_BIND = 4096
_REMOUNT = 32
_RDONLY = 1
_NOSUID = 2
_NODEV = 4
_NOEXEC = 8
_STORE = Path("/guard-approved-mappings")


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode)


def _path(value):
    if not isinstance(value, str) or "\x00" in value or not Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError("Invalid executable mapping path.")
    return Path(value)


def validate_records(records, *, approved_paths):
    if not isinstance(records, list) or not 0 < len(records) <= _MAX_RECORDS:
        raise ValueError("Invalid executable mapping count.")
    validated, seen, targets, total = [], set(), set(), 0
    for record in records:
        if not isinstance(record, dict) or record.keys() != {"path", "identity", "sha256", "targets"}:
            raise ValueError("Invalid executable mapping fields.")
        path = _path(record["path"])
        identity, digest, aliases = record["identity"], record["sha256"], record["targets"]
        if path not in approved_paths or path in seen:
            raise ValueError("Unbound executable mapping.")
        if not isinstance(identity, list) or len(identity) != 5 or any(type(v) is not int or v < 0 for v in identity):
            raise ValueError("Invalid executable mapping identity.")
        if not 0 < identity[2] <= _MAX_FILE or not stat.S_ISREG(identity[4]):
            raise ValueError("Invalid executable mapping type or size.")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("Invalid executable mapping hash.")
        if not isinstance(aliases, list) or not 0 < len(aliases) <= _MAX_TARGETS:
            raise ValueError("Invalid executable mapping aliases.")
        aliases = tuple(_path(alias) for alias in aliases)
        if path not in aliases or len(set(aliases)) != len(aliases) or targets.intersection(aliases):
            raise ValueError("Ambiguous executable mapping aliases.")
        seen.add(path)
        targets.update(aliases)
        total += identity[2]
        if total > _MAX_TOTAL or len(targets) > _MAX_TARGETS:
            raise ValueError("Executable mapping budget exceeded.")
        validated.append((path, tuple(identity), digest, aliases))
    return validated


def mount_targets(raw):
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("Mount snapshot exceeds its budget.")
    records = raw.splitlines()
    if not 0 < len(records) <= 4096:
        raise ValueError("Invalid namespace mount count.")
    targets = {}
    for record in records:
        fields = record.split()
        if len(fields) < 10 or b"-" not in fields[6:]:
            raise ValueError("Malformed namespace mount snapshot.")
        encoded = fields[4]
        decoded = re.sub(rb"\\([0-7]{3})", lambda match: bytes([int(match[1], 8)]), encoded)
        target = _path(os.fsdecode(decoded))
        options = set(fields[5].split(b","))
        if not ({b"ro", b"rw"} & options) or {b"ro", b"rw"} <= options:
            raise ValueError("Ambiguous namespace mount permissions.")
        flags = _NOSUID | _NOEXEC | (_RDONLY if b"ro" in options else 0) | (_NODEV if b"nodev" in options else 0)
        targets[target] = flags
    return sorted(targets.items(), key=lambda item: len(item[0].parts), reverse=True)


def _mount(libc, source, target, flags):
    source = None if source is None else os.fsencode(source)
    if libc.mount(source, os.fsencode(target), None, flags, None) != 0:
        raise OSError(ctypes.get_errno(), "Linux executable mapping mount failed.")


def _seal_copy(path, identity, digest, destination):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    copy = None
    try:
        before = os.fstat(descriptor)
        if _identity(before) != identity:
            raise ValueError("Executable mapping changed before copying.")
        copy = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        measured, count = hashlib.sha256(), 0
        while count < identity[2]:
            chunk = os.read(descriptor, min(1024 * 1024, identity[2] - count))
            if not chunk:
                raise ValueError("Executable mapping was truncated.")
            measured.update(chunk)
            pending = memoryview(chunk)
            while pending:
                written = os.write(copy, pending)
                if written <= 0:
                    raise OSError("Executable mapping copy did not progress.")
                pending = pending[written:]
            count += len(chunk)
        if os.read(descriptor, 1) or _identity(os.fstat(descriptor)) != identity or measured.hexdigest() != digest:
            raise ValueError("Executable mapping content changed.")
        os.fchmod(copy, 0o500)
        result, copy = copy, None
        return result
    finally:
        os.close(descriptor)
        if copy is not None:
            os.close(copy)


class _Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def drop_capabilities(libc):
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(47, 4, 0, 0, 0) != 0:
        raise ValueError("Linux privilege escalation could not be disabled.")
    valid = []
    for capability in range(64):
        state = libc.prctl(23, capability, 0, 0, 0)
        if state < 0:
            if ctypes.get_errno() != errno.EINVAL:
                raise ValueError("Linux capability discovery failed.")
            continue
        valid.append(capability)
        if libc.prctl(24, capability, 0, 0, 0) != 0:
            raise ValueError("Linux bounding capability drop failed.")
    header, data = _Header(0x20080522, 0), (_Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise ValueError("Linux active capability drop failed.")
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise ValueError("Linux active capability verification failed.")
    if any(item.effective or item.permitted or item.inheritable for item in data):
        raise ValueError("Linux active capabilities remain.")
    if any(libc.prctl(23, capability, 0, 0, 0) != 0 for capability in valid) or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise ValueError("Linux privilege boundary did not persist.")


def enforce_mapping_boundary(records, *, approved_paths):
    validated = validate_records(records, approved_paths=approved_paths)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    # Same-UID host processes must not acquire writable snapshot handles while
    # the private store is being populated. Exec happens only after it is RO.
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise ValueError("Linux setup process inspection could not be disabled.")
    with open("/proc/self/mountinfo", "rb") as stream:
        mounts = mount_targets(stream.read(8 * 1024 * 1024 + 1))
    if _STORE not in dict(mounts) or not _STORE.is_dir() or next(_STORE.iterdir(), None) is not None:
        raise ValueError("The private Linux mapping store is unavailable.")
    _STORE.chmod(0o700)
    for target, flags in mounts:
        _mount(libc, None, target, _BIND | _REMOUNT | flags)
        if not os.statvfs(target).f_flag & os.ST_NOEXEC:
            raise ValueError("Linux noexec mount was not enforced.")
    identities = {}
    for index, (path, identity, digest, aliases) in enumerate(validated):
        destination = _STORE / str(index)
        descriptor = _seal_copy(path, identity, digest, destination)
        try:
            sealed = os.fstat(descriptor)
            for target in aliases:
                target_fd = os.open(target, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if _identity(os.fstat(target_fd)) != identity:
                        raise ValueError("Executable mapping alias changed.")
                finally:
                    os.close(target_fd)
                _mount(libc, destination, target, _BIND)
                _mount(libc, None, target, _BIND | _REMOUNT | _RDONLY | _NOSUID | _NODEV)
                actual = target.stat()
                if (actual.st_dev, actual.st_ino) != (sealed.st_dev, sealed.st_ino) or os.statvfs(
                    target
                ).f_flag & os.ST_NOEXEC:
                    raise ValueError("Linux sealed mapping mount was not enforced.")
                identities[target] = (actual.st_dev, actual.st_ino)
        finally:
            os.close(descriptor)
    _mount(libc, None, _STORE, _BIND | _REMOUNT | _RDONLY | _NOSUID | _NODEV | _NOEXEC)
    if os.statvfs(_STORE).f_flag & (os.ST_RDONLY | os.ST_NOEXEC) != os.ST_RDONLY | os.ST_NOEXEC:
        raise ValueError("Linux immutable mapping store was not enforced.")
    drop_capabilities(libc)
    return identities
