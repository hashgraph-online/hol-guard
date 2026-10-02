"""Trusted single-threaded namespace entrypoint, before repository execution.

The owner creates this private hashed plan only after native authorization.
This internal launcher cannot grant consent and never retries without isolation.
It imports just the adjacent packaged kernel boundary, not repository modules.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

_FIELDS = frozenset(
    {
        "schema",
        "command",
        "read_roots",
        "read_files",
        "list_roots",
        "write_roots",
        "executables",
        "read_identities",
        "write_identities",
        "device_files",
    }
)
_MAX_BYTES = 64 * 1024 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Linux plan field.")
        result[key] = value
    return result


def load_plan(path: Path, digest: str) -> dict:
    if not path.is_absolute() or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Invalid private Linux plan locator.")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("Unsafe Linux plan directory.")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_BYTES
            ):
                raise ValueError("Unsafe Linux plan file.")
            raw = stream.read(_MAX_BYTES + 1)
    finally:
        os.close(parent)
    if len(raw) > _MAX_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("Linux execution plan changed.")
    plan = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(plan, dict) or plan.keys() != _FIELDS or plan["schema"] != "guard-linux-readonly-plan.v1":
        raise ValueError("Unsupported Linux execution plan.")
    command = plan["command"]
    if (
        not isinstance(command, list)
        or not 0 < len(command) <= 4096
        or any(not isinstance(arg, str) or "\x00" in arg for arg in command)
        or sum(len(arg.encode()) for arg in command) > 1_048_576
    ):
        raise ValueError("Invalid Linux command vector.")
    total = 0
    for field in ("read_roots", "read_files", "list_roots", "write_roots", "executables", "device_files"):
        paths = plan[field]
        if not isinstance(paths, list) or any(
            not isinstance(p, str) or "\x00" in p or not Path(p).is_absolute() for p in paths
        ):
            raise ValueError("Invalid Linux path vector.")
        total += len(paths)
        plan[field] = tuple(Path(p) for p in paths)
    if total > 250_000 or not Path(command[0]).is_absolute():
        raise ValueError("Linux plan exceeds its boundary.")
    for field, source in (("read_identities", "read_files"), ("write_identities", "write_roots")):
        records = plan[field]
        if not isinstance(records, list) or len(records) != len(plan[source]):
            raise ValueError("Incomplete Linux inode evidence.")
        identities = {}
        for record in records:
            if (
                not isinstance(record, list)
                or len(record) != 3
                or not isinstance(record[0], str)
                or any(type(v) is not int or not 0 <= v < 2**64 for v in record[1:])
            ):
                raise ValueError("Invalid Linux inode evidence.")
            key = Path(record[0])
            if key in identities:
                raise ValueError("Ambiguous Linux inode evidence.")
            identities[key] = tuple(record[1:])
        if identities.keys() != set(plan[source]):
            raise ValueError("Mismatched Linux inode evidence.")
        plan[field] = identities
    if Path(command[0]).resolve(strict=True) not in plan["executables"]:
        raise ValueError("The command does not resolve to an approved image.")
    return plan


def main() -> int:
    try:
        if len(sys.argv) != 3:
            raise ValueError("The private Linux plan requires its hash.")
        plan = load_plan(Path(sys.argv[1]), sys.argv[2])
        for path, identity in plan["write_identities"].items():
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
                raise ValueError("Linux output boundary changed.")
        boundary_path = Path(__file__).resolve().with_name("restricted_linux_landlock.py")
        spec = importlib.util.spec_from_file_location("guard_linux_boundary", boundary_path)
        if spec is None or spec.loader is None:
            raise ValueError("The packaged Linux boundary is unavailable.")
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        boundary.enforce_landlock(
            **{
                key: plan[key]
                for key in (
                    "read_roots",
                    "read_files",
                    "list_roots",
                    "write_roots",
                    "executables",
                    "read_identities",
                    "device_files",
                )
            }
        )
        boundary.enforce_socket_boundary()
        os.execv(plan["command"][0], plan["command"])
    except Exception:
        # Do not expose private plan paths/data or pretend the protected command ran.
        print(
            "HOL Guard could not enforce the validated Linux execution boundary. Execution was not started.",
            file=sys.stderr,
        )
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
