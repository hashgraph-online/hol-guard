"""Generation-bound managed removal authorization and tombstone evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from .acl import verify_protected_ownership_and_acl
from .continuity import verify_installation_continuity
from .contracts import MDM_STATUS_SCHEMA_VERSION, MachinePaths, default_machine_paths

_AUTHORIZATION_KEYS = {
    "actor",
    "expiresAt",
    "home",
    "installationGeneration",
    "issuedAt",
    "machineInstallationId",
    "nonce",
    "operation",
    "reason",
    "user",
}
_IDENTIFIER = re.compile(r"^[0-9a-f]{32}$")
_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$")
_MAX_TOMBSTONES = 4096
_TOMBSTONE_TRANSITIONS: dict[str | None, frozenset[str]] = {
    None: frozenset({"issued", "started"}),
    "issued": frozenset({"started"}),
    "started": frozenset({"completed", "failed"}),
}


@dataclass(frozen=True, slots=True)
class RemovalAuthorizationEvidence:
    fingerprint: str
    actor: str
    reason: str
    machine_installation_id: str
    installation_generation: str
    issued_at: str
    expires_at: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _active_binding(paths: MachinePaths) -> tuple[str, str]:
    verification = verify_installation_continuity(paths)
    record = verification.record
    if record is None or verification.identity_reason_code != "installation_identity_active":
        raise ValueError("mdm_removal_authorization_installation_unavailable")
    return record.machine_installation_id, record.installation_generation


def _is_administrator() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _authorization_owner_is_trusted(metadata: os.stat_result) -> bool:
    return platform.system() == "Windows" or (metadata.st_uid == 0 and metadata.st_mode & 0o077 == 0)


def _authorization_root_is_trusted(paths: MachinePaths) -> bool:
    return verify_protected_ownership_and_acl(paths).healthy


def _validate_actor_reason(actor: str, reason: str) -> None:
    if _ACTOR.fullmatch(actor) is None:
        raise ValueError("mdm_removal_authorization_actor_invalid")
    if not 1 <= len(reason) <= 256 or any(ord(character) < 32 for character in reason):
        raise ValueError("mdm_removal_authorization_reason_invalid")


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("mdm_removal_authorization_invalid")
    return value


def authorize_deactivation(
    home: Path,
    user: str,
    *,
    actor: str,
    reason: str,
    token_name: str | None = None,
) -> dict[str, object]:
    if not _is_administrator():
        raise PermissionError("mdm_administrator_context_required")
    if not home.is_absolute() or not home.is_dir():
        raise ValueError("mdm_home_not_found")
    if platform.system() != "Windows":
        import pwd

        try:
            account = pwd.getpwnam(user)
        except KeyError as exc:
            raise ValueError("mdm_user_not_found") from exc
        if home.resolve().stat().st_uid != account.pw_uid:
            raise ValueError("mdm_home_owner_mismatch")
    _validate_actor_reason(actor, reason)
    paths = default_machine_paths()
    machine_installation_id, installation_generation = _active_binding(paths)
    if not _authorization_root_is_trusted(paths):
        raise ValueError("mdm_removal_authorization_untrusted_root")
    root = paths.state_root / "removal-authorizations"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    now = _now()
    issued_at = now.isoformat()
    expires_at = (now + timedelta(minutes=2)).isoformat()
    resolved_name = token_name or f"{user}-{secrets.token_hex(8)}.json"
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.json", resolved_name) is None:
        raise ValueError("mdm_removal_authorization_name_invalid")
    target = root / resolved_name
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(
            {
                "actor": actor,
                "expiresAt": expires_at,
                "home": str(home.resolve()),
                "installationGeneration": installation_generation,
                "issuedAt": issued_at,
                "machineInstallationId": machine_installation_id,
                "nonce": secrets.token_urlsafe(24),
                "operation": "deactivate",
                "reason": reason,
                "user": user,
            },
            stream,
            sort_keys=True,
        )
        _ = stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o600)
    _fsync_directory(root)
    fingerprint = hashlib.sha256(target.read_bytes()).hexdigest()
    evidence = RemovalAuthorizationEvidence(
        fingerprint,
        actor,
        reason,
        machine_installation_id,
        installation_generation,
        issued_at,
        expires_at,
    )
    try:
        _ = record_removal_tombstone(evidence, status="issued", machine_paths=paths)
    except (OSError, ValueError):
        target.unlink(missing_ok=True)
        _fsync_directory(root)
        raise
    return {
        "schemaVersion": MDM_STATUS_SCHEMA_VERSION,
        "operation": "authorize-deactivation",
        "generatedAt": now.isoformat(),
        "scope": "user",
        "home": str(home.resolve()),
        "user": user,
        "authorizationPath": str(target),
        "authorizationFingerprint": fingerprint,
        "machineInstallationId": machine_installation_id,
        "installationGeneration": installation_generation,
    }


def validate_removal_authorization(
    path: Path,
    *,
    home: Path,
    user: str,
) -> RemovalAuthorizationEvidence:
    paths = default_machine_paths()
    if not _authorization_root_is_trusted(paths):
        raise ValueError("mdm_removal_authorization_untrusted_root")
    resolved_root = paths.state_root / "removal-authorizations"
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("mdm_removal_authorization_consumed_or_missing") from exc
    if not resolved.is_relative_to(resolved_root.resolve()) or not resolved.is_file():
        raise ValueError("mdm_removal_authorization_wrong_scope")
    try:
        content_bytes = resolved.read_bytes()
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("mdm_removal_authorization_invalid") from exc
    if len(content_bytes) > 16 * 1024 or metadata.st_size != len(content_bytes):
        raise ValueError("mdm_removal_authorization_invalid")
    if not _authorization_owner_is_trusted(metadata):
        raise ValueError("mdm_removal_authorization_untrusted_owner")
    try:
        raw_payload: object = json.loads(content_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("mdm_removal_authorization_invalid") from exc
    if not isinstance(raw_payload, dict):
        raise ValueError("mdm_removal_authorization_invalid")
    payload = cast(dict[str, object], raw_payload)
    if set(payload) != _AUTHORIZATION_KEYS:
        raise ValueError("mdm_removal_authorization_invalid")
    if payload.get("operation") != "deactivate" or payload.get("user") != user:
        raise ValueError("mdm_removal_authorization_wrong_scope")
    if payload.get("home") != str(home):
        raise ValueError("mdm_removal_authorization_wrong_scope")
    actor = _required_string(payload, "actor")
    reason = _required_string(payload, "reason")
    machine_installation_id = _required_string(payload, "machineInstallationId")
    installation_generation = _required_string(payload, "installationGeneration")
    _ = _required_string(payload, "nonce")
    issued_raw = _required_string(payload, "issuedAt")
    expires_raw = _required_string(payload, "expiresAt")
    if _IDENTIFIER.fullmatch(machine_installation_id) is None:
        raise ValueError("mdm_removal_authorization_invalid")
    if _IDENTIFIER.fullmatch(installation_generation) is None:
        raise ValueError("mdm_removal_authorization_invalid")
    _validate_actor_reason(actor, reason)
    try:
        issued = datetime.fromisoformat(issued_raw)
        expires = datetime.fromisoformat(expires_raw)
    except ValueError as exc:
        raise ValueError("mdm_removal_authorization_invalid") from exc
    now = _now()
    if issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= now:
        raise ValueError("mdm_removal_authorization_expired")
    if (expires - issued).total_seconds() > 300 or (now - issued).total_seconds() > 300:
        raise ValueError("mdm_removal_authorization_expired")
    if (machine_installation_id, installation_generation) != _active_binding(paths):
        raise ValueError("mdm_removal_authorization_wrong_generation")
    fingerprint = hashlib.sha256(content_bytes).hexdigest()
    try:
        resolved.unlink()
        _fsync_directory(resolved.parent)
    except OSError as exc:
        raise PermissionError("mdm_removal_authorization_not_consumable") from exc
    return RemovalAuthorizationEvidence(
        fingerprint,
        actor,
        reason,
        machine_installation_id,
        installation_generation,
        issued_raw,
        expires_raw,
    )


def record_removal_tombstone(
    evidence: RemovalAuthorizationEvidence,
    *,
    status: str,
    machine_paths: MachinePaths | None = None,
) -> Path:
    if status not in {"issued", "started", "completed", "failed"}:
        raise ValueError("mdm_removal_tombstone_status_invalid")
    paths = machine_paths or default_machine_paths()
    root = paths.state_root / "removal-tombstones"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    target = root / f"{evidence.fingerprint}.json"
    if not target.exists():
        with os.scandir(root) as entries:
            file_count = sum(1 for entry in entries if entry.is_file(follow_symlinks=False))
        if file_count >= _MAX_TOMBSTONES:
            raise OSError("mdm_removal_tombstone_capacity_exceeded")
    static_payload = {
        "actor": evidence.actor,
        "authorizationExpiresAt": evidence.expires_at,
        "authorizationFingerprint": evidence.fingerprint,
        "authorizationIssuedAt": evidence.issued_at,
        "installationGeneration": evidence.installation_generation,
        "machineInstallationId": evidence.machine_installation_id,
        "operation": "deactivate",
        "reason": evidence.reason,
        "schemaVersion": "hol-guard-removal-tombstone.v1",
    }
    events: list[dict[str, str]] = []
    previous_status: str | None = None
    if target.exists():
        try:
            existing_raw: object = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("mdm_removal_tombstone_invalid") from exc
        if not isinstance(existing_raw, dict):
            raise ValueError("mdm_removal_tombstone_invalid")
        existing = cast(dict[str, object], existing_raw)
        if set(existing) != set(static_payload) | {"events", "status", "updatedAt"}:
            raise ValueError("mdm_removal_tombstone_invalid")
        if any(existing.get(key) != value for key, value in static_payload.items()):
            raise ValueError("mdm_removal_tombstone_identity_mismatch")
        existing_events_raw = existing.get("events")
        if not isinstance(existing_events_raw, list):
            raise ValueError("mdm_removal_tombstone_invalid")
        existing_events = cast(list[object], existing_events_raw)
        if not 1 <= len(existing_events) <= 3:
            raise ValueError("mdm_removal_tombstone_invalid")
        event_previous_status: str | None = None
        event_previous_time: datetime | None = None
        for event_raw in existing_events:
            if not isinstance(event_raw, dict):
                raise ValueError("mdm_removal_tombstone_invalid")
            event = cast(dict[str, object], event_raw)
            if set(event) != {"at", "status"}:
                raise ValueError("mdm_removal_tombstone_invalid")
            event_status = event.get("status")
            event_at = event.get("at")
            if not isinstance(event_status, str) or not isinstance(event_at, str):
                raise ValueError("mdm_removal_tombstone_invalid")
            try:
                event_time = datetime.fromisoformat(event_at)
            except ValueError as exc:
                raise ValueError("mdm_removal_tombstone_invalid") from exc
            if event_time.tzinfo is None or (event_previous_time is not None and event_time < event_previous_time):
                raise ValueError("mdm_removal_tombstone_invalid")
            if event_status not in _TOMBSTONE_TRANSITIONS.get(event_previous_status, frozenset()):
                raise ValueError("mdm_removal_tombstone_invalid")
            events.append({"at": event_at, "status": event_status})
            event_previous_status = event_status
            event_previous_time = event_time
        previous_status = events[-1]["status"]
        if existing.get("status") != previous_status or existing.get("updatedAt") != events[-1]["at"]:
            raise ValueError("mdm_removal_tombstone_invalid")
    if status not in _TOMBSTONE_TRANSITIONS.get(previous_status, frozenset()):
        raise ValueError("mdm_removal_tombstone_transition_invalid")
    updated_at = _now().isoformat()
    events.append({"at": updated_at, "status": status})
    payload = static_payload | {"events": events, "status": status, "updatedAt": updated_at}
    temporary = root / f".{evidence.fingerprint}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            _ = stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
        _fsync_directory(root)
    finally:
        temporary.unlink(missing_ok=True)
    return target


__all__ = [
    "RemovalAuthorizationEvidence",
    "authorize_deactivation",
    "record_removal_tombstone",
    "validate_removal_authorization",
]
