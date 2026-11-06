"""Generation-bound managed removal authorization and tombstone evidence.

The native runtime writes and parses the authorization and tombstone files.
This module keeps the privileged checks: administrator context, the account
that owns the home, the trusted state root, the authorization file's owner
and the active installation binding.
"""

from __future__ import annotations

import base64
import os
import platform
from dataclasses import dataclass
from pathlib import Path

from ..durable_io import fsync_directory as _fsync_directory
from .acl import verify_protected_ownership_and_acl
from .continuity import verify_installation_continuity
from .contracts import MDM_STATUS_SCHEMA_VERSION, MachinePaths, default_machine_paths
from .runtime_request import runtime_answer

REMOVAL_EVIDENCE_FEATURE = "native-removal-evidence-v1"
REMOVAL_EVIDENCE_COMMAND = "removal-evidence"
REMOVAL_EVIDENCE_SCHEMA = "removal-evidence.v1"
_MAX_AUTHORIZATION_BYTES = 16 * 1024
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class RemovalAuthorizationEvidence:
    fingerprint: str
    actor: str
    reason: str
    machine_installation_id: str
    installation_generation: str
    issued_at: str
    expires_at: str


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


def _native_answer(request: dict[str, object]) -> dict[str, object] | None:
    """The runtime's answer to one removal-evidence request, or ``None`` when it cannot answer."""

    return runtime_answer(
        REMOVAL_EVIDENCE_FEATURE,
        REMOVAL_EVIDENCE_COMMAND,
        {"schema": REMOVAL_EVIDENCE_SCHEMA, **request},
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )


def _native_fields(request: dict[str, object], *, unavailable: Exception) -> dict[str, object]:
    """Fields of a successful answer; a refusal raises its own error code."""

    answer = _native_answer(request)
    if answer is None or not isinstance(answer.get("ok"), bool):
        # Evidence nothing could check never authorizes a removal.
        raise unavailable
    if answer["ok"] is True:
        return answer
    error = answer.get("error")
    code = error if isinstance(error, str) else "mdm_removal_evidence_invalid"
    if answer.get("kind") == "os":
        raise OSError(code)
    raise ValueError(code)


def _native_string(fields: dict[str, object], key: str, *, unavailable: Exception | None = None) -> str:
    value = fields.get(key)
    if not isinstance(value, str):
        raise unavailable or ValueError("mdm_removal_authorization_native_unavailable")
    return value


def _evidence(fields: dict[str, object]) -> RemovalAuthorizationEvidence:
    return RemovalAuthorizationEvidence(
        _native_string(fields, "fingerprint"),
        _native_string(fields, "actor"),
        _native_string(fields, "reason"),
        _native_string(fields, "machine_installation_id"),
        _native_string(fields, "installation_generation"),
        _native_string(fields, "issued_at"),
        _native_string(fields, "expires_at"),
    )


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
    paths = default_machine_paths()
    machine_installation_id, installation_generation = _active_binding(paths)
    if not _authorization_root_is_trusted(paths):
        raise ValueError("mdm_removal_authorization_untrusted_root")
    root = paths.state_root / "removal-authorizations"
    issued = _native_fields(
        {
            "op": "issue",
            "root": str(root),
            "name": token_name or None,
            "home": str(home.resolve()),
            "user": user,
            "actor": actor,
            "reason": reason,
            "machine_installation_id": machine_installation_id,
            "installation_generation": installation_generation,
        },
        unavailable=ValueError("mdm_removal_authorization_native_unavailable"),
    )
    target = Path(_native_string(issued, "path"))
    fingerprint = _native_string(issued, "fingerprint")
    issued_at = _native_string(issued, "issued_at")
    evidence = RemovalAuthorizationEvidence(
        fingerprint,
        actor,
        reason,
        machine_installation_id,
        installation_generation,
        issued_at,
        _native_string(issued, "expires_at"),
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
        "generatedAt": issued_at,
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
    if len(content_bytes) > _MAX_AUTHORIZATION_BYTES or metadata.st_size != len(content_bytes):
        raise ValueError("mdm_removal_authorization_invalid")
    if not _authorization_owner_is_trusted(metadata):
        raise ValueError("mdm_removal_authorization_untrusted_owner")
    evidence = _evidence(
        _native_fields(
            {
                "op": "check",
                "content": base64.b64encode(content_bytes).decode("ascii"),
                "home": str(home),
                "user": user,
            },
            unavailable=ValueError("mdm_removal_authorization_native_unavailable"),
        )
    )
    if (evidence.machine_installation_id, evidence.installation_generation) != _active_binding(paths):
        raise ValueError("mdm_removal_authorization_wrong_generation")
    try:
        resolved.unlink()
        _fsync_directory(resolved.parent)
    except OSError as exc:
        raise PermissionError("mdm_removal_authorization_not_consumable") from exc
    return evidence


def record_removal_tombstone(
    evidence: RemovalAuthorizationEvidence,
    *,
    status: str,
    machine_paths: MachinePaths | None = None,
) -> Path:
    paths = machine_paths or default_machine_paths()
    recorded = _native_fields(
        {
            "op": "tombstone",
            "root": str(paths.state_root / "removal-tombstones"),
            "status": status,
            "evidence": {
                "fingerprint": evidence.fingerprint,
                "actor": evidence.actor,
                "reason": evidence.reason,
                "machine_installation_id": evidence.machine_installation_id,
                "installation_generation": evidence.installation_generation,
                "issued_at": evidence.issued_at,
                "expires_at": evidence.expires_at,
            },
        },
        unavailable=OSError("mdm_removal_native_unavailable"),
    )
    return Path(_native_string(recorded, "path", unavailable=OSError("mdm_removal_native_unavailable")))


__all__ = [
    "RemovalAuthorizationEvidence",
    "authorize_deactivation",
    "record_removal_tombstone",
    "validate_removal_authorization",
]
