"""Bounded, read-only identities for the diagnostic transition observer."""

from __future__ import annotations

import functools
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import psutil

DIRECTORY = "producer-observation"
CONFIG_ENV = "HOL_GUARD_TRANSITION_OBSERVER_CONTEXT"
MAX_RECORDS = 256
MAX_LEDGER_BYTES = 128 * 1024
MAX_PROCESSES = 32
MAX_REPORT_BYTES = 48 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(value: str | Path) -> str | None:
    try:
        path = Path(value)
        metadata = path.stat()
        if metadata.st_size > 64 * 1024 * 1024:
            return None
        fields = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        return _cached_file_digest(str(path), fields)
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=128)
def _cached_file_digest(path: str, fields: tuple[int, int, int, int, int]) -> str | None:
    data = Path(path).read_bytes()
    after = Path(path).stat()
    if fields != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        return None
    return sha256(data)


def private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("observer_directory_invalid")
    if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ValueError("observer_directory_not_private")


def identity(pid: int) -> dict[str, Any]:
    """Keep unavailable identity distinct from observed absence or process exit."""
    result = {"pid": pid, "identity_status": "unknown"}
    try:
        process = psutil.Process(pid)
        if sys.platform == "linux":
            raw = Path(f"/proc/{pid}/stat").read_text()
            marker = "linux_ticks_" + raw[raw.rfind(")") + 2 :].split()[19]
        else:
            marker = "creation_" + str(process.create_time()).replace(".", "_")
        result["start_marker"] = marker
        if process.status() == psutil.STATUS_ZOMBIE:
            result["identity_status"] = "exited_not_reaped"
            return result
        executable_digest = file_digest(process.exe())
        if executable_digest is not None:
            result.update(identity_status="observed", executable_sha256=executable_digest)
    except psutil.NoSuchProcess:
        result["identity_status"] = "not_present"
    except (psutil.Error, OSError, ValueError, IndexError):
        pass
    return result


def operation_metadata(value: object) -> dict[str, Any]:
    """Describe argv by digest and a narrow enum; never retain its text."""
    if not isinstance(value, (tuple, list)) or not value or not all(isinstance(item, str) for item in value):
        return {"operation_kind": "unclassified", "arguments_valid": False}
    arguments = list(value)
    kind = "unclassified"
    if len(arguments) in {2, 3} and arguments[1:] in (
        ["capabilities"],
        ["capabilities", "--json"],
        ["self-test"],
        ["self-test", "--json"],
    ):
        kind = "native_nonspawning_probe"
    elif len(arguments) == 4 and arguments[1:3] == ["resident-stop", "--state-dir"]:
        kind = "native_stop"
    elif len(arguments) > 1 and arguments[1] in {
        "resident-client",
        "resident-client-stream",
        "hook-client",
        "supervise-managed",
        "serve-managed",
        "serve",
    }:
        kind = "native_producer"
    elif any("multiprocessing.resource_tracker" in item for item in arguments):
        kind = "resource_tracker"
    elif any("multiprocessing.spawn" in item for item in arguments):
        kind = "python_spawn"
    return {
        "operation_kind": kind,
        "arguments_valid": True,
        "arguments_sha256": sha256(json.dumps(arguments, separators=(",", ":")).encode()),
        "executable_sha256": file_digest(arguments[0]),
        # Source/argv matching requires independent review. A familiar verb is not attestation.
        "nonspawning_attested": False,
    }


def result_metadata(value: object) -> dict[str, Any]:
    result = {}
    returned = getattr(value, "returncode", None)
    result["return_code"] = returned if type(returned) is int else None
    for field in ("timed_out", "containment_failed", "output_limit_exceeded"):
        observed = getattr(value, field, None)
        result["limit_exceeded" if field == "output_limit_exceeded" else field] = (
            observed if type(observed) is bool else None
        )
    return result


def observer_directory(fixture_root: Path) -> Path:
    return fixture_root.parent / DIRECTORY
