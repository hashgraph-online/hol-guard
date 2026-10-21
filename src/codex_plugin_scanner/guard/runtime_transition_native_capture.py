"""Read-only owned native identity candidates; these never prove protection.

The caller must still obtain fresh configured-hook Rust receipts before admission.
No process arguments, environment, signals, runtime overrides or authority writes.
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .daemon.live_identity import DaemonArtifactBinding, verified_live_guard_daemon_identity
from .native_runtime import NativeRuntimeIdentity

MAX_CHILDREN = 32
MAX_PROCESS_DEPTH = 3
MAX_NATIVE_BYTES = 64 * 1024 * 1024


class NativeCaptureError(ValueError):
    """Bounded, non-sensitive capture refusal."""


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    uid: int
    start_token: str
    executable: Path


@dataclass(frozen=True)
class OwnedNativeCandidate:
    """Kernel ownership and file identity only, never a native admission seal."""

    identity: NativeRuntimeIdentity
    daemon: ProcessSnapshot
    processes: tuple[ProcessSnapshot, ...]
    workers: tuple[ProcessSnapshot, ...]


def _check(deadline: float) -> None:
    if isinstance(deadline, bool) or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise NativeCaptureError("native_capture_deadline")


class _BSDInfo(ctypes.Structure):
    # Apple XNU bsd/sys/proc_info.h: struct proc_bsdinfo, PROC_PIDTBSDINFO=3.
    _fields_ = (
        [
            (name, ctypes.c_uint32)
            for name in (
                "flags",
                "status",
                "xstatus",
                "pid",
                "ppid",
                "uid",
                "gid",
                "ruid",
                "rgid",
                "svuid",
                "svgid",
                "reserved",
            )
        ]
        + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        + [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")]
        + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]
    )


def _darwin_api():
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    library.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    library.proc_listchildpids.restype = ctypes.c_int
    return library


class _DarwinSigInfo(ctypes.Structure):
    # Apple XNU bsd/sys/signal.h: siginfo_t (the sigval union has pointer alignment).
    _fields_ = [(name, ctypes.c_int) for name in ("signo", "errno", "code", "pid")] + [
        ("uid", ctypes.c_uint32),
        ("status", ctypes.c_int),
        ("addr", ctypes.c_void_p),
        ("value", ctypes.c_void_p),
        ("band", ctypes.c_long),
        ("pad", ctypes.c_ulong * 7),
    ]


def darwin_child_has_exited(pid: int) -> bool:
    """Observe an owned child's exit through native waitid without reaping it.

    Darwin Python may omit os.waitid while libc exports the POSIX API. WNOWAIT
    preserves the owner's status; errors, nonchildren and live children refuse.
    """
    if sys.platform != "darwin" or not 0 < pid <= 2**31 - 1:
        return False
    try:
        waitid = ctypes.CDLL(None, use_errno=True).waitid
        waitid.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(_DarwinSigInfo), ctypes.c_int]
        waitid.restype = ctypes.c_int
        info = _DarwinSigInfo()
        result = waitid(os.P_PID, pid, ctypes.byref(info), os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return result == 0 and info.pid == pid and info.code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
    except (OSError, ValueError, AttributeError):
        return False


def _read_proc(path: Path, maximum: int, deadline: float) -> bytes:
    _check(deadline)
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    _check(deadline)
    if len(value) > maximum:
        raise NativeCaptureError("native_capture_capacity")
    return value


def _process_snapshot(pid: int, deadline: float) -> ProcessSnapshot:
    _check(deadline)
    if not 0 < pid <= 2_147_483_647:
        raise NativeCaptureError("native_capture_process_invalid")
    if sys.platform == "darwin":
        api = _darwin_api()
        info = _BSDInfo()
        size = ctypes.sizeof(info)
        if api.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size or info.pid != pid:
            raise NativeCaptureError("native_capture_process_unavailable")
        buffer = ctypes.create_string_buffer(4096)
        count = api.proc_pidpath(pid, buffer, len(buffer))
        if count <= 0 or count >= len(buffer):
            raise NativeCaptureError("native_capture_process_unavailable")
        path = Path(os.fsdecode(buffer.value))
        result = ProcessSnapshot(pid, info.ppid, info.uid, f"darwin:{info.start_sec}:{info.start_usec}", path)
        # The executable lookup must refer to the same incarnation as BSD info.
        again = _BSDInfo()
        if api.proc_pidinfo(pid, 3, 0, ctypes.byref(again), size) != size or (
            again.pid,
            again.ppid,
            again.uid,
            again.start_sec,
            again.start_usec,
        ) != (info.pid, info.ppid, info.uid, info.start_sec, info.start_usec):
            raise NativeCaptureError("native_capture_process_changed")
        again_path = ctypes.create_string_buffer(4096)
        if api.proc_pidpath(pid, again_path, len(again_path)) <= 0 or again_path.value != buffer.value:
            raise NativeCaptureError("native_capture_process_changed")
    elif sys.platform == "linux":
        root = Path("/proc") / str(pid)
        raw = _read_proc(root / "stat", 4096, deadline)
        fields = raw.rpartition(b")")[2].split()
        if len(fields) < 20 or not fields[1].isdigit() or not fields[19].isdigit():
            raise NativeCaptureError("native_capture_process_invalid")
        # proc directory ownership is process ownership, not executable-file ownership.
        # A non-dumpable process may appear root-owned; refuse it conservatively.
        owner = root.stat().st_uid
        path = Path(os.readlink(root / "exe"))
        result = ProcessSnapshot(pid, int(fields[1]), owner, "linux:" + fields[19].decode("ascii"), path)
        again_fields = _read_proc(root / "stat", 4096, deadline).rpartition(b")")[2].split()
        if (again_fields[1], again_fields[19], root.stat().st_uid, os.readlink(root / "exe")) != (
            fields[1],
            fields[19],
            owner,
            str(path),
        ):
            raise NativeCaptureError("native_capture_process_changed")
    else:
        raise NativeCaptureError("native_capture_platform_unsupported")
    _check(deadline)
    if not result.executable.is_absolute() or not result.start_token:
        raise NativeCaptureError("native_capture_process_invalid")
    return result


def _child_pids(pid: int, deadline: float) -> tuple[int, ...]:
    _check(deadline)
    if sys.platform == "darwin":
        values = (ctypes.c_int * (MAX_CHILDREN + 1))()
        count = _darwin_api().proc_listchildpids(pid, values, ctypes.sizeof(values))
        if count < 0:
            raise NativeCaptureError("native_capture_process_unavailable")
        if count > MAX_CHILDREN:
            raise NativeCaptureError("native_capture_capacity")
        result = tuple(values[:count])
    elif sys.platform == "linux":
        raw = _read_proc(Path(f"/proc/{pid}/task/{pid}/children"), 4096, deadline)
        values = raw.split()
        if len(values) > MAX_CHILDREN:
            raise NativeCaptureError("native_capture_capacity")
        if any(not value.isdigit() for value in values):
            raise NativeCaptureError("native_capture_process_invalid")
        result = tuple(int(value) for value in values)
    else:
        raise NativeCaptureError("native_capture_platform_unsupported")
    _check(deadline)
    if len(set(result)) != len(result) or any(not 0 < value <= 2_147_483_647 for value in result):
        raise NativeCaptureError("native_capture_process_invalid")
    return result


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _native_identity(path: Path, deadline: float) -> NativeRuntimeIdentity:
    _check(deadline)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or not before.st_mode & 0o111
        or before.st_mode & 0o022
        or before.st_uid not in {0, os.getuid()}
        or not 0 < before.st_size <= MAX_NATIVE_BYTES
    ):
        raise NativeCaptureError("native_capture_file_unsafe")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        if _fingerprint(os.fstat(handle.fileno())) != _fingerprint(before):
            raise NativeCaptureError("native_capture_file_changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            _check(deadline)
            chunk = handle.read(min(64 * 1024, before.st_size - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > before.st_size:
                raise NativeCaptureError("native_capture_file_changed")
            digest.update(chunk)
        if total != before.st_size or _fingerprint(os.fstat(handle.fileno())) != _fingerprint(before):
            raise NativeCaptureError("native_capture_file_changed")
    if _fingerprint(path.lstat()) != _fingerprint(before):
        raise NativeCaptureError("native_capture_file_changed")
    _check(deadline)
    return NativeRuntimeIdentity(path, before.st_size, before.st_mtime_ns, digest.hexdigest())


def capture_owned_native_candidate(
    guard_home: Path,
    expected_artifact: DaemonArtifactBinding,
    *,
    deadline_monotonic: float,
) -> OwnedNativeCandidate:
    """Capture one native file below bounded, exactly identified Core workers.

    The authenticated main and kernel start identities must agree before/after.
    OS calls are checked around the call; they are not themselves interruptible.
    File replacement after capture remains possible: retain/pin bytes immediately,
    then qualify the digest with actual native hook receipts before admitting it.
    """
    deadline = deadline_monotonic
    _check(deadline)
    try:
        state = verified_live_guard_daemon_identity(
            guard_home,
            expected_artifact=expected_artifact,
            deadline_monotonic=deadline,
        )
        pid = state.get("pid") if state else None
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise NativeCaptureError("native_capture_daemon_unverified")
        parent = _process_snapshot(pid, deadline)
        if parent.executable != expected_artifact.executable or parent.uid != os.getuid():
            raise NativeCaptureError("native_capture_daemon_changed")
        selected: list[ProcessSnapshot] = []
        workers: list[ProcessSnapshot] = []
        pending = [(parent, 0)]
        visited = {pid}
        while pending:
            owner, depth = pending.pop()
            children = _child_pids(owner.pid, deadline)
            if len(children) + len(visited) - 1 > MAX_CHILDREN:
                raise NativeCaptureError("native_capture_capacity")
            if children and depth >= MAX_PROCESS_DEPTH:
                raise NativeCaptureError("native_capture_capacity")
            for child_pid in children:
                if child_pid in visited:
                    raise NativeCaptureError("native_capture_ownership_changed")
                visited.add(child_pid)
                child = _process_snapshot(child_pid, deadline)
                if child.ppid != owner.pid or child.uid != parent.uid:
                    raise NativeCaptureError("native_capture_ownership_changed")
                if child.executable.name in {"hol-guard-runtime", "hol-guard-runtime.exe"}:
                    selected.append(child)
                elif child.executable == parent.executable:
                    # multiprocessing spawn/frozen bootloader workers only.
                    workers.append(child)
                    pending.append((child, depth + 1))
        if not selected:
            raise NativeCaptureError("native_capture_missing")
        if len({child.executable for child in selected}) != 1:
            raise NativeCaptureError("native_capture_ambiguous")
        identity = _native_identity(selected[0].executable, deadline)
        if any(_process_snapshot(child.pid, deadline) != child for child in (*selected, *workers)):
            raise NativeCaptureError("native_capture_process_changed")
        if (
            _process_snapshot(pid, deadline) != parent
            or verified_live_guard_daemon_identity(
                guard_home,
                expected_artifact=expected_artifact,
                deadline_monotonic=deadline,
            )
            != state
        ):
            raise NativeCaptureError("native_capture_daemon_changed")
        _check(deadline)
        return OwnedNativeCandidate(identity, parent, tuple(selected), tuple(workers))
    except (OSError, UnicodeError, IndexError) as error:
        raise NativeCaptureError("native_capture_process_unavailable") from error
