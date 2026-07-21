"""Authenticated browser-to-daemon reconnect proofs for dashboard updates."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import TypedDict, TypeGuard

from .discovery import (
    canonical_discovery_payload,
    discovery_key_id,
    load_daemon_discovery_key,
    sign_discovery_payload,
)

DASHBOARD_RECONNECT_PROTOCOL_VERSION = 1
DASHBOARD_RECONNECT_AUTHORIZATION_TTL_SECONDS = 5 * 60
DASHBOARD_RECONNECT_CHALLENGE_TTL_SECONDS = 10
DASHBOARD_RECONNECT_SURFACE = "dashboard"
DASHBOARD_RECONNECT_STORE_FILE = "dashboard-reconnect-authorizations.json"
DASHBOARD_RECONNECT_STORE_SCHEMA = "guard.dashboard-reconnect-authorizations.v1"
DASHBOARD_RECONNECT_STORE_SIGNATURE_FIELD = "signature"
DASHBOARD_RECONNECT_MAX_AUTHORIZATIONS = 32
_PRIVATE_FILE_MODE = 0o600
_NONCE_HEX_LENGTH = 64
_MAX_STORE_BYTES = 64 * 1024


class DashboardReconnectAuthorization(TypedDict):
    reconnect_id: str
    surface: str
    issued_at_ms: int
    expires_at_ms: int
    installation_id: str
    guard_home_id: str


class DashboardReconnectChallenge(TypedDict):
    protocol_version: int
    reconnect_id: str
    client_nonce: str
    server_nonce: str
    state_id: str
    candidate_origin: str
    installation_id: str
    guard_home_id: str
    surface: str
    issued_at_ms: int
    expires_at_ms: int


def dashboard_reconnect_guard_home_id(guard_home: Path) -> str:
    """Return a non-reversible identity for one canonical Guard home."""

    resolved = str(guard_home.expanduser().resolve()).encode("utf-8")
    return hashlib.sha256(resolved).hexdigest()


def prepare_dashboard_reconnect_authorization(
    guard_home: Path,
    *,
    now_ms: int | None = None,
) -> dict[str, object]:
    """Persist and return one browser-held verifier before an update restart."""

    discovery_key = load_daemon_discovery_key(guard_home)
    if discovery_key is None:
        raise RuntimeError("daemon discovery identity is unavailable")
    issued_at_ms = _current_time_ms(now_ms)
    authorization: DashboardReconnectAuthorization = {
        "reconnect_id": secrets.token_hex(32),
        "surface": DASHBOARD_RECONNECT_SURFACE,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms + DASHBOARD_RECONNECT_AUTHORIZATION_TTL_SECONDS * 1000,
        "installation_id": discovery_key_id(discovery_key),
        "guard_home_id": dashboard_reconnect_guard_home_id(guard_home),
    }
    records = _load_authorizations(guard_home, discovery_key=discovery_key)
    if records is None:
        raise RuntimeError("dashboard reconnect authorization state is invalid")
    live_records = [record for record in records if record["expires_at_ms"] >= issued_at_ms]
    live_records.append(authorization)
    live_records = sorted(live_records, key=lambda item: item["issued_at_ms"])[-DASHBOARD_RECONNECT_MAX_AUTHORIZATIONS:]
    _write_authorizations(guard_home, discovery_key=discovery_key, records=live_records)
    return {
        "protocol_version": DASHBOARD_RECONNECT_PROTOCOL_VERSION,
        **authorization,
        "verifier": _authorization_verifier(discovery_key, authorization),
    }


def issue_dashboard_reconnect_challenge(
    guard_home: Path,
    *,
    reconnect_id: object,
    client_nonce: object,
    candidate_origin: object,
    state_id: object,
    now_ms: int | None = None,
) -> tuple[dict[str, object] | None, str]:
    """Issue a short-lived server proof for a prepared browser verifier."""

    if not _is_hex_nonce(reconnect_id) or not _is_hex_nonce(client_nonce):
        return None, "dashboard_reconnect_malformed_challenge"
    if not isinstance(candidate_origin, str) or not candidate_origin or not isinstance(state_id, str) or not state_id:
        return None, "dashboard_reconnect_malformed_challenge"
    discovery_key = load_daemon_discovery_key(guard_home)
    if discovery_key is None:
        return None, "dashboard_reconnect_identity_unavailable"
    authorization = _find_authorization(
        guard_home,
        discovery_key=discovery_key,
        reconnect_id=reconnect_id,
    )
    if authorization is None:
        return None, "dashboard_reconnect_authorization_unavailable"
    issued_at_ms = _current_time_ms(now_ms)
    if not _authorization_is_current(
        authorization,
        guard_home=guard_home,
        discovery_key=discovery_key,
        now_ms=issued_at_ms,
    ):
        return None, "dashboard_reconnect_authorization_expired"
    challenge: DashboardReconnectChallenge = {
        "protocol_version": DASHBOARD_RECONNECT_PROTOCOL_VERSION,
        "reconnect_id": reconnect_id.lower(),
        "client_nonce": client_nonce.lower(),
        "server_nonce": secrets.token_hex(32),
        "state_id": state_id,
        "candidate_origin": candidate_origin,
        "installation_id": authorization["installation_id"],
        "guard_home_id": authorization["guard_home_id"],
        "surface": authorization["surface"],
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": min(
            authorization["expires_at_ms"],
            issued_at_ms + DASHBOARD_RECONNECT_CHALLENGE_TTL_SECONDS * 1000,
        ),
    }
    verifier = _authorization_verifier(discovery_key, authorization)
    return {
        **challenge,
        "proof": dashboard_reconnect_proof(verifier, "server", challenge),
    }, "dashboard_reconnect_challenge_issued"


def consume_dashboard_reconnect_challenge(
    guard_home: Path,
    *,
    challenge: dict[str, object],
    proof: object,
    expected_candidate_origin: str,
    expected_state_id: str,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """Verify one browser proof against a prepared reconnect authorization."""

    normalized = _normalized_challenge(challenge)
    if normalized is None or not isinstance(proof, str) or not _is_hex_digest(proof):
        return False, "dashboard_reconnect_malformed_proof"
    current_time_ms = _current_time_ms(now_ms)
    if normalized["expires_at_ms"] < current_time_ms or normalized["issued_at_ms"] > current_time_ms:
        return False, "dashboard_reconnect_proof_expired"
    if (
        normalized["candidate_origin"] != expected_candidate_origin
        or normalized["state_id"] != expected_state_id
        or normalized["surface"] != DASHBOARD_RECONNECT_SURFACE
    ):
        return False, "dashboard_reconnect_proof_context_mismatch"
    discovery_key = load_daemon_discovery_key(guard_home)
    if discovery_key is None:
        return False, "dashboard_reconnect_identity_unavailable"
    records = _load_authorizations(guard_home, discovery_key=discovery_key)
    if records is None:
        return False, "dashboard_reconnect_authorization_unavailable"
    authorization = next(
        (record for record in records if record["reconnect_id"] == normalized["reconnect_id"]),
        None,
    )
    if authorization is None or not _authorization_is_current(
        authorization,
        guard_home=guard_home,
        discovery_key=discovery_key,
        now_ms=current_time_ms,
    ):
        return False, "dashboard_reconnect_authorization_unavailable"
    if (
        normalized["installation_id"] != authorization["installation_id"]
        or normalized["guard_home_id"] != authorization["guard_home_id"]
    ):
        return False, "dashboard_reconnect_proof_context_mismatch"
    verifier = _authorization_verifier(discovery_key, authorization)
    expected_proof = dashboard_reconnect_proof(verifier, "client", normalized)
    if not secrets.compare_digest(proof.lower(), expected_proof):
        return False, "dashboard_reconnect_proof_invalid"
    return True, "dashboard_reconnect_proof_accepted"


def dashboard_reconnect_proof(
    verifier: str,
    proof_context: str,
    challenge: DashboardReconnectChallenge,
) -> str:
    """Return the canonical HMAC used by browser and daemon proof steps."""

    key = bytes.fromhex(verifier)
    payload: dict[str, object] = {"proof_context": proof_context, **challenge}
    return hmac.new(key, canonical_discovery_payload(payload), hashlib.sha256).hexdigest()


def dashboard_reconnect_challenge_identity(challenge: dict[str, object]) -> str | None:
    """Return the replay-cache identity of the normalized authenticated challenge."""

    normalized = _normalized_challenge(challenge)
    if normalized is None:
        return None
    normalized_payload: dict[str, object] = dict(normalized)
    return hashlib.sha256(canonical_discovery_payload(normalized_payload)).hexdigest()


def _authorization_verifier(
    discovery_key: str,
    authorization: DashboardReconnectAuthorization,
) -> str:
    return sign_discovery_payload(
        discovery_key,
        {"purpose": "guard-dashboard-reconnect-verifier-v1", **authorization},
    )


def _authorization_is_current(
    authorization: DashboardReconnectAuthorization,
    *,
    guard_home: Path,
    discovery_key: str,
    now_ms: int,
) -> bool:
    return (
        authorization["surface"] == DASHBOARD_RECONNECT_SURFACE
        and authorization["issued_at_ms"] <= now_ms <= authorization["expires_at_ms"]
        and authorization["installation_id"] == discovery_key_id(discovery_key)
        and authorization["guard_home_id"] == dashboard_reconnect_guard_home_id(guard_home)
    )


def _normalized_challenge(value: dict[str, object]) -> DashboardReconnectChallenge | None:
    string_fields = (
        "reconnect_id",
        "client_nonce",
        "server_nonce",
        "state_id",
        "candidate_origin",
        "installation_id",
        "guard_home_id",
        "surface",
    )
    if value.get("protocol_version") != DASHBOARD_RECONNECT_PROTOCOL_VERSION:
        return None
    if not all(isinstance(value.get(field), str) and bool(value.get(field)) for field in string_fields):
        return None
    issued_at_ms = value.get("issued_at_ms")
    expires_at_ms = value.get("expires_at_ms")
    if not isinstance(issued_at_ms, int) or not isinstance(expires_at_ms, int):
        return None
    if not all(
        _is_hex_nonce(value.get(field))
        for field in ("reconnect_id", "client_nonce", "server_nonce", "installation_id", "guard_home_id")
    ):
        return None
    return DashboardReconnectChallenge(
        protocol_version=DASHBOARD_RECONNECT_PROTOCOL_VERSION,
        reconnect_id=str(value["reconnect_id"]).lower(),
        client_nonce=str(value["client_nonce"]).lower(),
        server_nonce=str(value["server_nonce"]).lower(),
        state_id=str(value["state_id"]),
        candidate_origin=str(value["candidate_origin"]),
        installation_id=str(value["installation_id"]).lower(),
        guard_home_id=str(value["guard_home_id"]).lower(),
        surface=str(value["surface"]),
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    )


def _find_authorization(
    guard_home: Path,
    *,
    discovery_key: str,
    reconnect_id: str,
) -> DashboardReconnectAuthorization | None:
    records = _load_authorizations(guard_home, discovery_key=discovery_key)
    if records is None:
        return None
    return next((record for record in records if record["reconnect_id"] == reconnect_id.lower()), None)


def _load_authorizations(
    guard_home: Path,
    *,
    discovery_key: str,
) -> list[DashboardReconnectAuthorization] | None:
    path = guard_home / DASHBOARD_RECONNECT_STORE_FILE
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_STORE_BYTES:
            return None
        if os.name != "nt" and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            return None
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            payload = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    finally:
        os.close(descriptor)
    if not isinstance(payload, dict) or payload.get("schema") != DASHBOARD_RECONNECT_STORE_SCHEMA:
        return None
    signature = payload.get(DASHBOARD_RECONNECT_STORE_SIGNATURE_FIELD)
    if not isinstance(signature, str):
        return None
    unsigned = {key: value for key, value in payload.items() if key != DASHBOARD_RECONNECT_STORE_SIGNATURE_FIELD}
    if not hmac.compare_digest(signature, sign_discovery_payload(discovery_key, unsigned)):
        return None
    raw_records = unsigned.get("records")
    if not isinstance(raw_records, list) or len(raw_records) > DASHBOARD_RECONNECT_MAX_AUTHORIZATIONS:
        return None
    records: list[DashboardReconnectAuthorization] = []
    for raw in raw_records:
        record = _normalized_authorization(raw)
        if record is None:
            return None
        records.append(record)
    return records


def _normalized_authorization(value: object) -> DashboardReconnectAuthorization | None:
    if not isinstance(value, dict):
        return None
    if not all(_is_hex_nonce(value.get(field)) for field in ("reconnect_id", "installation_id", "guard_home_id")):
        return None
    if value.get("surface") != DASHBOARD_RECONNECT_SURFACE:
        return None
    issued_at_ms = value.get("issued_at_ms")
    expires_at_ms = value.get("expires_at_ms")
    if not isinstance(issued_at_ms, int) or not isinstance(expires_at_ms, int) or expires_at_ms < issued_at_ms:
        return None
    return DashboardReconnectAuthorization(
        reconnect_id=str(value["reconnect_id"]).lower(),
        surface=DASHBOARD_RECONNECT_SURFACE,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
        installation_id=str(value["installation_id"]).lower(),
        guard_home_id=str(value["guard_home_id"]).lower(),
    )


def _write_authorizations(
    guard_home: Path,
    *,
    discovery_key: str,
    records: list[DashboardReconnectAuthorization],
) -> None:
    unsigned: dict[str, object] = {
        "schema": DASHBOARD_RECONNECT_STORE_SCHEMA,
        "records": records,
    }
    payload = {
        **unsigned,
        DASHBOARD_RECONNECT_STORE_SIGNATURE_FIELD: sign_discovery_payload(discovery_key, unsigned),
    }
    guard_home.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".dashboard-reconnect.", dir=guard_home)
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, guard_home / DASHBOARD_RECONNECT_STORE_FILE)
    finally:
        os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def _current_time_ms(value: int | None) -> int:
    if value is not None:
        return value
    import time

    return int(time.time() * 1000)


def _is_hex_nonce(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == _NONCE_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value.lower())
    )


def _is_hex_digest(value: object) -> TypeGuard[str]:
    return _is_hex_nonce(value)
