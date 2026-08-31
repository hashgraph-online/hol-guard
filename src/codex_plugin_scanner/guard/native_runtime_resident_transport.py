"""Socket ownership and authenticated framing for the resident native runtime."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import socket
import stat
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_SOCKET_PATH_BYTES = 100
_AUTH_TOKEN_BYTES = 32
_AUTH_NONCE_BYTES = 32
_AUTH_PROOF_BYTES = 32
_AUTH_TIMEOUT_SECONDS = 0.25
_FRAME_REQUEST_ID_BYTES = 32
_FRAME_DIGEST_BYTES = 32
_FRAME_HEADER_BYTES = 4 + _FRAME_REQUEST_ID_BYTES + _FRAME_DIGEST_BYTES + 4
_REQUEST_MAGIC = b"HGR2"
_RESPONSE_MAGIC = b"HGS2"
_SERVER_PROOF_LABEL = b"hol-guard-resident-server-v1\x00"
_CLIENT_PROOF_LABEL = b"hol-guard-resident-client-v1\x00"


def _private_runtime_dir(guard_home: Path) -> Path | None:
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        return None
    try:
        resolved_guard_home = guard_home.expanduser().resolve(strict=True)
        guard_metadata = resolved_guard_home.lstat()
        if stat.S_ISLNK(guard_metadata.st_mode) or not stat.S_ISDIR(guard_metadata.st_mode):
            return None
        runtime_dir = resolved_guard_home / "native-runtime"
        runtime_dir.mkdir(mode=0o700, exist_ok=True)
        metadata = runtime_dir.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return None
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and getattr(metadata, "st_uid", current_uid) != current_uid:
            return None
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            runtime_dir.chmod(0o700)
            metadata = runtime_dir.lstat()
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                return None
        return runtime_dir.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None


def _resident_socket_path(guard_home: Path, identity_sha256: str) -> Path | None:
    runtime_dir = _private_runtime_dir(guard_home)
    if runtime_dir is None:
        return None
    suffix = identity_sha256[:16] if identity_sha256 else "unknown"
    socket_path = runtime_dir / f"hook-v2-{suffix}.sock"
    if len(os.fsencode(socket_path)) > _MAX_SOCKET_PATH_BYTES:
        return None
    return socket_path


@contextmanager
def _resident_start_lock(socket_path: Path | None, *, timeout_seconds: float) -> Generator[bool]:
    if os.name == "nt" or socket_path is None:
        yield True
        return
    import fcntl

    lock_path = socket_path.with_suffix(".start.lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError:
        yield False
        return
    acquired = False
    try:
        try:
            os.fchmod(descriptor, 0o600)
        except OSError:
            yield False
            return
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            except OSError:
                break
        yield acquired
    finally:
        if acquired:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(descriptor)


def _unix_socket_accepts_connections(socket_path: Path | None) -> bool:
    if socket_path is None or not hasattr(socket, "AF_UNIX"):
        return False
    client: socket.socket | None = None
    try:
        metadata = socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode):
            return False
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(_AUTH_TIMEOUT_SECONDS)
        client.connect(str(socket_path))
        return True
    except OSError:
        return False
    finally:
        if client is not None:
            client.close()


def _socket_identity(socket_path: Path) -> tuple[int, int] | None:
    try:
        metadata = socket_path.lstat()
    except OSError:
        return None
    if not stat.S_ISSOCK(metadata.st_mode):
        return None
    return metadata.st_dev, metadata.st_ino


def _unlink_owned_socket(socket_path: Path | None, *, expected_identity: tuple[int, int] | None) -> None:
    if socket_path is None or expected_identity is None:
        return
    try:
        metadata = socket_path.lstat()
        if stat.S_ISSOCK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == expected_identity:
            socket_path.unlink()
    except (FileNotFoundError, OSError):
        pass


def _select_loopback_address() -> tuple[str, int] | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            host, port = probe.getsockname()[:2]
            if host != "127.0.0.1" or not isinstance(port, int) or port <= 0:
                return None
            return host, port
    except OSError:
        return None


def _proof(token: bytes, label: bytes, nonce: bytes) -> bytes:
    return hmac.new(token, label + nonce, hashlib.sha256).digest()


def _read_exact(client: socket.socket, length: int) -> bytes | None:
    if length < 0:
        return None
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = client.recv(min(remaining, 64 * 1024))
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _authenticate_client(client: socket.socket, token: bytes, *, timeout_seconds: float) -> bool:
    if len(token) != _AUTH_TOKEN_BYTES or timeout_seconds <= 0:
        return False
    try:
        client.settimeout(min(timeout_seconds, _AUTH_TIMEOUT_SECONDS))
        nonce = secrets.token_bytes(_AUTH_NONCE_BYTES)
        client.sendall(nonce)
        server_proof = _read_exact(client, _AUTH_PROOF_BYTES)
        expected_server = _proof(token, _SERVER_PROOF_LABEL, nonce)
        if server_proof is None or not hmac.compare_digest(server_proof, expected_server):
            return False
        client.sendall(_proof(token, _CLIENT_PROOF_LABEL, nonce))
        client.settimeout(timeout_seconds)
        return True
    except (OSError, OverflowError):
        return False


def _authenticated_loopback_client(
    address: tuple[str, int], token: bytes, *, timeout_seconds: float
) -> socket.socket | None:
    client: socket.socket | None = None
    try:
        client = socket.create_connection(address, timeout=timeout_seconds)
        if _authenticate_client(client, token, timeout_seconds=timeout_seconds):
            return client
    except (OSError, OverflowError):
        pass
    if client is not None:
        client.close()
    return None


def _authenticated_unix_client(socket_path: Path, token: bytes, *, timeout_seconds: float) -> socket.socket | None:
    if not hasattr(socket, "AF_UNIX"):
        return None
    client: socket.socket | None = None
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout_seconds)
        client.connect(str(socket_path))
        if _authenticate_client(client, token, timeout_seconds=timeout_seconds):
            return client
    except (OSError, OverflowError):
        pass
    if client is not None:
        client.close()
    return None


def _frame_request(payload: bytes) -> tuple[bytes, bytes]:
    if not payload or len(payload) > _MAX_REQUEST_BYTES:
        raise ValueError("native resident payload is outside the accepted bound")
    request_id = secrets.token_bytes(_FRAME_REQUEST_ID_BYTES)
    digest = hashlib.sha256(payload).digest()
    header = _REQUEST_MAGIC + request_id + digest + len(payload).to_bytes(4, "big")
    assert len(header) == _FRAME_HEADER_BYTES
    return request_id, header + payload


def _read_bound_response(client: socket.socket, request_id: bytes) -> bytes | None:
    header = _read_exact(client, _FRAME_HEADER_BYTES)
    if header is None or header[:4] != _RESPONSE_MAGIC:
        return None
    response_request_id = header[4 : 4 + _FRAME_REQUEST_ID_BYTES]
    if not hmac.compare_digest(response_request_id, request_id):
        return None
    digest_start = 4 + _FRAME_REQUEST_ID_BYTES
    response_digest = header[digest_start : digest_start + _FRAME_DIGEST_BYTES]
    length = int.from_bytes(header[-4:], "big")
    if length <= 0 or length > _MAX_RESPONSE_BYTES:
        return None
    response = _read_exact(client, length)
    if response is None:
        return None
    if not hmac.compare_digest(hashlib.sha256(response).digest(), response_digest):
        return None
    return response


def _send_authenticated_request(
    client: socket.socket,
    token: bytes,
    payload: bytes,
    *,
    timeout_seconds: float,
) -> bytes | None:
    if timeout_seconds <= 0:
        return None
    try:
        with client:
            if not _authenticate_client(client, token, timeout_seconds=timeout_seconds):
                return None
            request_id, frame = _frame_request(payload)
            client.sendall(frame)
            return _read_bound_response(client, request_id)
    except (OSError, OverflowError, ValueError):
        return None


def _send_authenticated_loopback_request(
    address: tuple[str, int], token: bytes, payload: bytes, *, timeout_seconds: float
) -> bytes | None:
    try:
        client = socket.create_connection(address, timeout=timeout_seconds)
    except (OSError, OverflowError):
        return None
    return _send_authenticated_request(client, token, payload, timeout_seconds=timeout_seconds)


def _send_authenticated_unix_request(
    socket_path: Path, token: bytes, payload: bytes, *, timeout_seconds: float
) -> bytes | None:
    if not hasattr(socket, "AF_UNIX"):
        return None
    client: socket.socket | None = None
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout_seconds)
        client.connect(str(socket_path))
    except (OSError, OverflowError):
        if client is not None:
            client.close()
        return None
    return _send_authenticated_request(client, token, payload, timeout_seconds=timeout_seconds)
