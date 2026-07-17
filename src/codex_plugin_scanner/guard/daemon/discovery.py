"""Authenticated local-daemon discovery state and challenge primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path

DAEMON_DISCOVERY_PROTOCOL_VERSION = 1
DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS = 5
DAEMON_DISCOVERY_KEY_FILE = "daemon-discovery-key"
DAEMON_STATE_SIGNATURE_FIELD = "state_signature"
DAEMON_CHALLENGE_PROOF_FIELD = "proof"
_PRIVATE_FILE_MODE = 0o600
_DISCOVERY_KEY_BYTES = 32


def daemon_discovery_key_path(guard_home: Path) -> Path:
    return guard_home / DAEMON_DISCOVERY_KEY_FILE


def _private_file_text(path: Path) -> str | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return None
    if os.name != "nt" and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        return None
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def load_daemon_discovery_key(guard_home: Path) -> str | None:
    encoded = _private_file_text(daemon_discovery_key_path(guard_home))
    if encoded is None or len(encoded) != _DISCOVERY_KEY_BYTES * 2:
        return None
    try:
        bytes.fromhex(encoded)
    except ValueError:
        return None
    return encoded.lower()


def ensure_daemon_discovery_key(guard_home: Path) -> str:
    guard_home.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # Semgrep's file-permission rule recommends 0o644, which is unsafe for
        # this secret-bearing directory; owner-only access is intentional.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(guard_home, 0o700)
    existing = load_daemon_discovery_key(guard_home)
    if existing is not None:
        return existing
    path = daemon_discovery_key_path(guard_home)
    encoded = secrets.token_hex(_DISCOVERY_KEY_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except FileExistsError:
        raced = load_daemon_discovery_key(guard_home)
        if raced is None:
            raise RuntimeError("Guard daemon discovery key is not a private regular file") from None
        return raced
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return encoded


def canonical_discovery_payload(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_discovery_payload(discovery_key: str, payload: dict[str, object]) -> str:
    key = bytes.fromhex(discovery_key)
    return hmac.new(key, canonical_discovery_payload(payload), hashlib.sha256).hexdigest()


def discovery_key_id(discovery_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(discovery_key)).hexdigest()


def authenticate_daemon_state(
    payload: dict[str, object],
    *,
    discovery_key: str,
) -> dict[str, object]:
    authenticated = dict(payload)
    authenticated["discovery_protocol_version"] = DAEMON_DISCOVERY_PROTOCOL_VERSION
    authenticated["discovery_key_id"] = discovery_key_id(discovery_key)
    authenticated[DAEMON_STATE_SIGNATURE_FIELD] = sign_discovery_payload(discovery_key, authenticated)
    return authenticated


def verify_daemon_state(payload: dict[str, object], *, discovery_key: str) -> bool:
    signature = payload.get(DAEMON_STATE_SIGNATURE_FIELD)
    if not isinstance(signature, str):
        return False
    unsigned = {key: value for key, value in payload.items() if key != DAEMON_STATE_SIGNATURE_FIELD}
    if unsigned.get("discovery_protocol_version") != DAEMON_DISCOVERY_PROTOCOL_VERSION:
        return False
    if unsigned.get("discovery_key_id") != discovery_key_id(discovery_key):
        return False
    expected = sign_discovery_payload(discovery_key, unsigned)
    return hmac.compare_digest(signature, expected)


def load_authenticated_daemon_state(guard_home: Path) -> dict[str, object] | None:
    discovery_key = load_daemon_discovery_key(guard_home)
    if discovery_key is None:
        return None
    raw = _private_file_text(guard_home / "daemon-state.json")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not verify_daemon_state(payload, discovery_key=discovery_key):
        return None
    return payload


def authenticated_challenge_payload(
    *,
    discovery_key: str,
    state: dict[str, object],
    nonce: str,
    hook_event: str,
    issued_at_ms: int,
    expires_at_ms: int,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "protocol_version": DAEMON_DISCOVERY_PROTOCOL_VERSION,
        "nonce": nonce,
        "state_id": state.get("state_id"),
        "host": state.get("host"),
        "port": state.get("port"),
        "pid": state.get("pid"),
        "started_at": state.get("started_at"),
        "guard_home": state.get("guard_home"),
        "hook_event": hook_event,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    payload[DAEMON_CHALLENGE_PROOF_FIELD] = sign_discovery_payload(discovery_key, payload)
    return payload
