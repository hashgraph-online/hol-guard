"""Bounded Linux process witnesses for the native diagnostic receiver.

This binds a live, explicitly owned fixture descendant at observation time.
It is diagnostic attribution, not a general concurrent-process attestation.
No command line, path, environment or credential bytes enter exported reports.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from scripts.native_slo_rust_phase_schema import ROLES

MAX_PROCESS_DEPTH = 16
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    parent: int
    group: int
    session: int
    start_ticks: int


def _refuse() -> None:
    raise ValueError("native_phase_process_refused")


def _read_at(directory: int, name: str, bound: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        chunks: list[bytes] = []
        remaining = bound + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > bound:
            _refuse()
        return value
    finally:
        os.close(descriptor)


def parse_stat(value: bytes, expected_pid: int) -> ProcessIdentity:
    text = value.decode("utf-8")
    head, fields_text = text.rsplit(") ", 1)
    pid = int(head.split(" (", 1)[0])
    fields = fields_text.split()
    if pid != expected_pid or len(fields) < 20 or fields[0] in {"Z", "X", "x"}:
        _refuse()
    row = ProcessIdentity(pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))
    if row.pid <= 0 or row.parent < 0 or row.group <= 0 or row.session <= 0 or row.start_ticks <= 0:
        _refuse()
    return row


def _same_executable(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class Executable:
    """Retain the exact caller-supplied binary descriptor and its source digest."""

    def __init__(self, path: Path) -> None:
        self.descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(self.descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES:
                _refuse()
            digest = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(self.descriptor, min(65536, MAX_EXECUTABLE_BYTES + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                digest.update(chunk)
                if count > MAX_EXECUTABLE_BYTES:
                    _refuse()
            self.identity = _same_executable(before)
            if count != before.st_size or _same_executable(os.fstat(self.descriptor)) != self.identity:
                _refuse()
            self.sha256 = digest.hexdigest()
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = -1
            raise

    def current(self) -> bool:
        return self.descriptor >= 0 and _same_executable(os.fstat(self.descriptor)) == self.identity

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def read_process(pid: int, executable: Executable | None = None) -> tuple[ProcessIdentity, str | None]:
    if type(pid) is not int or not 1 <= pid <= 2**31 - 1:
        _refuse()
    directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = parse_stat(_read_at(directory, "stat", 4096), pid)
        status = _read_at(directory, "status", 65536).decode("ascii")
        uid_rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        gid_rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Gid:")]
        if (
            len(uid_rows) != 1
            or len(gid_rows) != 1
            or uid_rows[0] != [str(os.geteuid())] * 4
            or gid_rows[0] != [str(os.getegid())] * 4
        ):
            _refuse()
        role = None
        if executable is not None:
            if not executable.current() or _same_executable(os.stat("exe", dir_fd=directory)) != executable.identity:
                _refuse()
            command = _read_at(directory, "cmdline", 16384)
            parts = command.split(b"\0")
            if len(parts) < 3 or parts[-1] != b"":
                _refuse()
            role = ROLES.get(parts[1].decode("ascii"))
            if role is None:
                _refuse()
        after = parse_stat(_read_at(directory, "stat", 4096), pid)
        if before != after:
            _refuse()
        if executable is not None and _same_executable(os.stat("exe", dir_fd=directory)) != executable.identity:
            _refuse()
        return before, role
    finally:
        os.close(directory)


class OwnedCohort:
    def __init__(self, fixture_pid: int, executable: Executable) -> None:
        root, _ = read_process(fixture_pid)
        if root.parent != os.getpid() or root.session != root.pid or root.group != root.pid:
            _refuse()
        self.root = root
        self.executable = executable
        self.seen: dict[int, tuple[int, str]] = {}

    def admit(self, pid: int, start_ticks: int, role: str) -> ProcessIdentity:
        sender, actual_role = read_process(pid, self.executable)
        if sender.start_ticks != start_ticks or actual_role != role:
            _refuse()
        if pid in self.seen and self.seen[pid] != (start_ticks, role):
            _refuse()
        if pid not in self.seen and len(self.seen) >= 16:
            _refuse()
        chain = [sender]
        for _ in range(MAX_PROCESS_DEPTH):
            current = chain[-1]
            if current.pid == self.root.pid:
                break
            if current.parent <= 1 or any(row.pid == current.parent for row in chain):
                _refuse()
            parent, _ = read_process(current.parent)
            if parent.start_ticks > current.start_ticks:
                _refuse()
            chain.append(parent)
        if chain[-1] != self.root:
            _refuse()
        # Re-read each exact process generation after walking the ancestry.
        # Any exit, reparenting or reuse makes this observation unavailable.
        for original in reversed(chain):
            current, _ = read_process(original.pid, self.executable if original.pid == sender.pid else None)
            if current != original:
                _refuse()
        self.seen[pid] = (start_ticks, role)
        return sender
