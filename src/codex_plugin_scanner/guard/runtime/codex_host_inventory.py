"""Read display metadata from an existing, same-user Codex host.

Only private, same-user Codex control sockets are eligible. No host or MCP process is started,
and public tool summaries never become schemas, account evidence, or permissions.
"""

from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import logging
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..codex_app_server import (
    _is_trusted_local_socket,
    _read_websocket_frame,
    _send_websocket_frame,
    _send_websocket_handshake,
    _send_websocket_text,
)
from ..strict_json_pairs import unique_json_object
from .bounded_json_depth import check_json_depth

_MAX_TOOLS = 10_000
_MAX_MESSAGES = 128
_MAX_JSON_DEPTH = 32
_SNAPSHOT_TTL = 30.0
_LOGGER = logging.getLogger(__name__)
_FAILURE_CODES = frozenset(
    {
        "codex_host_changed",
        "codex_host_untrusted",
        "codex_host_invalid",
        "codex_host_limit",
        "codex_host_timeout",
        "codex_host_unavailable",
    }
)
# The discovery job turns these into the banner's guidance, so they are part of
# this module's contract rather than an internal detail.
HOST_FAILURE_CODES = _FAILURE_CODES


class CodexHostInventoryCache:
    """Ephemeral public metadata, outside the grant store and request hot path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: (
            tuple[float, Path, tuple[Path, tuple[int, int, int, int]], int, int | None, dict[str, object]] | None
        ) = None

    def refresh(self, *, codex_home: Path, cancel: threading.Event) -> None:
        socket_path = codex_home / "app-server-control" / "app-server-control.sock"
        try:
            snapshot = read_codex_host_inventory(codex_home=codex_home, cancel=cancel)
            source = _socket_target(socket_path)
            pid = snapshot.host_pid
            if not _host_identity_matches(socket_path, pid, snapshot.managed_pid):
                raise ValueError("codex_host_changed")
            if snapshot.connection_id != _source_id(codex_home, os.geteuid(), pid, source[1]):
                raise ValueError("codex_host_changed")
        except (OSError, ValueError) as error:
            if isinstance(error, ValueError) and str(error) == "codex_host_cancelled":
                return
            with self._lock:
                self._snapshot = None
            if (
                isinstance(error, FileNotFoundError)
                or isinstance(error.__cause__, FileNotFoundError)
                or str(error) == "codex_host_unsupported"
            ):
                return
            reason = str(error) if str(error) in _FAILURE_CODES else "codex_host_invalid"
            _LOGGER.warning("Codex host inventory failed (%s)", reason)
            raise ValueError(reason) from None
        if cancel.is_set():
            return
        with self._lock:
            if not cancel.is_set():
                payload = snapshot.as_payload()
                payload["expires_at_ms"] = int((time.time() + _SNAPSHOT_TTL) * 1000)
                self._snapshot = (time.monotonic(), socket_path, source, pid, snapshot.managed_pid, payload)

    def read(self) -> dict[str, object] | None:
        with self._lock:
            snapshot = self._snapshot
        if snapshot is None:
            return None
        seen, socket_path, source, pid, managed_pid, payload = snapshot
        try:
            if (
                time.monotonic() - seen > _SNAPSHOT_TTL
                or _socket_target(socket_path) != source
                or not _host_identity_matches(socket_path, pid, managed_pid)
            ):
                return None
        except (OSError, ValueError):
            return None
        return copy.deepcopy(payload)


@dataclass(frozen=True, slots=True)
class CodexHostInventory:
    connection_id: str
    apps: tuple[dict[str, object], ...]
    metadata_complete: bool
    host_pid: int
    managed_pid: int | None

    def as_payload(self) -> dict[str, object]:
        return {
            "host": "Codex",
            "connection_id": self.connection_id,
            "catalog_coverage": "host-summary",
            "account_verified": False,
            "schemas_available": False,
            "permissions_granted": False,
            "snapshot_age": "unknown",
            "metadata_complete": self.metadata_complete,
            "apps": list(self.apps),
        }


def _managed_pid(socket_path: Path) -> int:
    pid_path = socket_path.parent / "hol-guard-app-server.pid"
    descriptor = os.open(pid_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or not 1 <= metadata.st_size <= 32
        ):
            raise ValueError("codex_host_untrusted")
        value = os.read(descriptor, 33).decode("ascii").strip()
    finally:
        os.close(descriptor)
    if not value.isascii() or not value.isdecimal() or not 1 < int(value) <= 2**31 - 1:
        raise ValueError("codex_host_untrusted")
    return int(value)


def _optional_managed_pid(socket_path: Path) -> int | None:
    try:
        (socket_path.parent / "hol-guard-app-server.pid").lstat()
    except FileNotFoundError:
        # Codex's own daemon does not create Guard's process marker.
        return None
    return _managed_pid(socket_path)


def _host_identity_matches(socket_path: Path, pid: int, expected: int | None) -> bool:
    tracked = _optional_managed_pid(socket_path)
    # Process identity is authenticated on the connected peer during refresh.
    # Cache reads only pin the private socket and marker, without spawning ps.
    return tracked == expected and (tracked == pid if tracked is not None else pid > 1)


def _peer_identity(client: socket.socket) -> tuple[int, int]:
    if sys.platform.startswith("linux"):
        pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return uid, pid
    if sys.platform == "darwin":
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        getpeereid = ctypes.CDLL(None, use_errno=True).getpeereid
        getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        getpeereid.restype = ctypes.c_int
        if getpeereid(client.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise ValueError("codex_host_untrusted")
        # macOS SOL_LOCAL / LOCAL_PEERPID authenticate the listening process.
        pid = struct.unpack("i", client.getsockopt(0, 2, 4))[0]
        return uid.value, pid
    raise ValueError("codex_host_unsupported")


def _is_codex_process(pid: int) -> bool:
    if sys.platform.startswith("linux"):
        name = Path(os.readlink(f"/proc/{pid}/exe")).name
        if name == "codex":
            return True
        if name == "rosetta":
            # Docker Desktop may expose the translator before the original argv.
            with Path(f"/proc/{pid}/cmdline").open("rb") as stream:
                arguments = stream.read(65_537)
            if len(arguments) > 65_536:
                return False
            argv = arguments.split(b"\0")
            if Path(argv[0].decode()).name == "codex":
                return True
            return (
                len(argv) >= 4
                and argv[0] == b"/run/rosetta/rosetta"
                and argv[1] == argv[2]
                and Path(argv[1].decode()).is_absolute()
                and Path(argv[1].decode()).name == "codex"
                and argv[3] == b"app-server"
            )
        return False
    if sys.platform == "darwin":
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
        return result.returncode == 0 and Path(result.stdout.strip()).name == "codex"
    return False


def _socket_target(socket_path: Path) -> tuple[Path, tuple[int, int, int, int]]:
    """Pin Codex's private socket alias and its private resolved socket."""
    source = socket_path.lstat()
    parent = socket_path.parent.lstat()
    if (
        source.st_uid != os.geteuid()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o077
    ):
        raise ValueError("codex_host_untrusted")
    target = socket_path
    if stat.S_ISLNK(source.st_mode):
        target = Path(os.readlink(socket_path))
        if not target.is_absolute():
            raise ValueError("codex_host_untrusted")
    if not _is_trusted_local_socket(target):
        raise ValueError("codex_host_untrusted")
    resolved = target.lstat()
    target_parent = target.parent.lstat()
    if target_parent.st_mode & 0o077:
        raise ValueError("codex_host_untrusted")
    return target, (source.st_dev, source.st_ino, resolved.st_dev, resolved.st_ino)


def _source_id(codex_home: Path, uid: int, pid: int, identity: tuple[int, int, int, int]) -> str:
    return hashlib.sha256(
        json.dumps(
            [
                str(codex_home),
                uid,
                pid,
                *identity,
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _reject_constant(_value: str) -> None:
    raise ValueError("codex_host_invalid")


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("codex_host_invalid")
    return cast(dict[str, object], value)


def _check_depth(payload: bytes) -> None:
    check_json_depth(payload, maximum=_MAX_JSON_DEPTH, error_code="codex_host_limit")


def _rpc(
    client: socket.socket,
    pending: bytearray,
    method: str,
    params: dict[str, object],
    *,
    deadline: float,
    cancel: threading.Event,
) -> dict[str, object]:
    # No caller-controlled method/refresh parameters or thread operations.
    if method not in {"initialize", "app/installed", "app/read"}:
        raise ValueError("codex_host_unsupported")
    request_id = secrets.token_hex(16)
    _send_websocket_text(client, json.dumps({"id": request_id, "method": method, "params": params}))
    for _ in range(_MAX_MESSAGES):
        remaining = deadline - time.monotonic()
        if cancel.is_set() or remaining <= 0:
            raise ValueError("codex_host_cancelled" if cancel.is_set() else "codex_host_timeout")
        client.settimeout(remaining)
        opcode, payload = _read_websocket_frame(client, pending)
        if opcode == 0x9:
            _send_websocket_frame(client, 0xA, payload)
            continue
        if opcode != 0x1:
            raise ValueError("codex_host_invalid")
        _check_depth(payload)
        message = _object(
            json.loads(payload.decode("utf-8"), object_pairs_hook=unique_json_object, parse_constant=_reject_constant)
        )
        if "id" not in message:
            if "method" not in message:
                raise ValueError("codex_host_invalid")
            continue
        if message["id"] != request_id or type(message["id"]) is not str:
            raise ValueError("codex_host_invalid")
        if "error" in message:
            raise ValueError("codex_host_unavailable")
        return _object(message.get("result"))
    raise ValueError("codex_host_limit")


def read_codex_host_inventory(
    *,
    codex_home: Path,
    timeout: float = 5.0,
    cancel: threading.Event | None = None,
) -> CodexHostInventory:
    """Read an existing host snapshot, without credentials, startup or grants."""
    cancel = cancel if cancel is not None else threading.Event()
    socket_path = codex_home / "app-server-control" / "app-server-control.sock"
    try:
        if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
            raise ValueError("codex_host_unsupported")
        if cancel.is_set():
            raise ValueError("codex_host_cancelled")
        target, socket_identity = _socket_target(socket_path)
        expected_pid = _optional_managed_pid(socket_path)
        deadline = time.monotonic() + min(max(timeout, 0.1), 10.0)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(max(0.1, deadline - time.monotonic()))
            client.connect(str(target))
            uid, pid = _peer_identity(client)
            if uid != os.geteuid() or (expected_pid is not None and pid != expected_pid) or not _is_codex_process(pid):
                raise ValueError("codex_host_untrusted")
            if _socket_target(socket_path) != (target, socket_identity):
                raise ValueError("codex_host_changed")
            pending = bytearray(_send_websocket_handshake(client))
            _rpc(
                client,
                pending,
                "initialize",
                {
                    "clientInfo": {"name": "hol_guard_inventory", "version": "1"},
                    "capabilities": {"experimentalApi": True},
                },
                deadline=deadline,
                cancel=cancel,
            )
            _send_websocket_text(client, '{"method":"initialized"}')
            result = _rpc(client, pending, "app/installed", {"forceRefresh": False}, deadline=deadline, cancel=cancel)
            apps = cast(list[dict[str, object]], _native_rows({"installed": result})["apps"])
            complete = True
            for start in range(0, len(apps), 100):
                page = apps[start : start + 100]
                result = _rpc(
                    client,
                    pending,
                    "app/read",
                    {
                        "appIds": [app["app_id"] for app in page],
                        "includeTools": True,
                    },
                    deadline=deadline,
                    cancel=cancel,
                )
                answer = _native_rows({"page": page, "read": result}, count=len(page))
                apps[start : start + 100] = cast(list[dict[str, object]], answer["apps"])
                complete = answer["complete"] is True and complete
                if sum(len(cast(list[object], app.get("tools", []))) for app in apps) > _MAX_TOOLS:
                    raise ValueError("codex_host_limit")
            if cancel.is_set() or not _host_identity_matches(socket_path, pid, expected_pid):
                raise ValueError("codex_host_changed")
            if _socket_target(socket_path) != (target, socket_identity):
                raise ValueError("codex_host_changed")
        return CodexHostInventory(
            _source_id(codex_home, uid, pid, socket_identity), tuple(apps), complete, pid, expected_pid
        )
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        raise ValueError("codex_host_unavailable") from error
    except ValueError as error:
        if not str(error).startswith("codex_host_"):
            raise ValueError("codex_host_invalid") from error
        raise


def _native_rows(request: dict[str, object], *, count: int | None = None) -> dict[str, object]:
    """Ask the native ``codex_host_inventory`` kind what a host reply says.

    Rust validates the reply and builds the public app rows; a reply it
    refuses carries the ``codex_host_*`` code to raise.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("codex_host_inventory", request)
    except NativeRunnerAuthorityError as error:
        raise ValueError(
            "codex_host_limit" if str(error).endswith("_too_large") else "codex_host_unavailable"
        ) from None
    code = answer.get("error")
    if code is not None:
        raise ValueError(code if isinstance(code, str) and code in _FAILURE_CODES else "codex_host_invalid")
    apps: object = answer.get("apps")
    rows = cast(list[object], apps) if isinstance(apps, list) else None
    if (
        rows is None
        or not all(isinstance(app, dict) for app in rows)
        or (count is not None and (len(rows) != count or type(answer.get("complete")) is not bool))
    ):
        raise ValueError("codex_host_invalid")
    return answer
