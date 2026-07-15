"""Prompt-free per-user activation and machine/user health operations."""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import logging
import os
import platform
import re
import secrets
import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ..adapters.base import HarnessContext
from ..cli.install_commands import apply_managed_install
from ..daemon.manager import retire_all_guard_daemons_for_home
from ..store import GuardStore
from .contracts import MDM_STATUS_SCHEMA_VERSION, default_machine_paths
from .manifest import verify_release_manifest
from .native import NativeInstallVerification, verify_native_install
from .policy import load_managed_policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base(operation: str) -> dict[str, object]:
    return {"schemaVersion": MDM_STATUS_SCHEMA_VERSION, "operation": operation, "generatedAt": _now()}


def _audit(path: Path, *, operation: str, status: str, scope: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=5, encoding="utf-8")
    try:
        handler.setFormatter(logging.Formatter("%(message)s"))
        record = logging.LogRecord("hol-guard-mdm", logging.INFO, "", 0, "", (), None)
        record.msg = json.dumps(
            {"timestamp": _now(), "operation": operation, "status": status, "scope": scope}, sort_keys=True
        )
        handler.emit(record)
    finally:
        handler.close()
    path.chmod(0o600)


def validate_user_home(home: str, user: str | None = None) -> Path:
    path = Path(home)
    if not path.is_absolute():
        raise ValueError("mdm_home_must_be_absolute")
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ValueError("mdm_home_not_found")
    if user is not None and platform.system() != "Windows":
        import pwd

        try:
            account = pwd.getpwnam(user)
        except KeyError as exc:
            raise ValueError("mdm_user_not_found") from exc
        if resolved.stat().st_uid != account.pw_uid:
            raise ValueError("mdm_home_owner_mismatch")
        if os.geteuid() != account.pw_uid:
            raise ValueError("mdm_user_context_mismatch")
    elif user is not None and getpass.getuser().casefold() != user.casefold():
        raise ValueError("mdm_user_context_mismatch")
    return resolved


def _is_administrator() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def authorize_deactivation(home: Path, user: str, *, token_name: str | None = None) -> dict[str, object]:
    """Create machine-owned authority without putting authorization material in arguments."""

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
    root = default_machine_paths().state_root / "removal-authorizations"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    now = datetime.now(timezone.utc)
    resolved_name = token_name or f"{user}-{secrets.token_hex(8)}.json"
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.json", resolved_name) is None:
        raise ValueError("mdm_removal_authorization_name_invalid")
    target = root / resolved_name
    target.write_text(
        json.dumps(
            {
                "operation": "deactivate",
                "user": user,
                "home": str(home.resolve()),
                "nonce": secrets.token_urlsafe(24),
                "issuedAt": now.isoformat(),
                "expiresAt": (now + timedelta(minutes=2)).isoformat(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    target.chmod(0o644)
    _audit(
        default_machine_paths().log_root / "mdm-lifecycle.log",
        operation="authorize-deactivation",
        status="authorized",
        scope="machine",
    )
    payload = _base("authorize-deactivation")
    payload.update(
        {
            "scope": "user",
            "home": str(home.resolve()),
            "user": user,
            "authorizationPath": str(target),
        }
    )
    return payload


def validate_removal_authorization(
    path: Path,
    *,
    home: Path,
    user: str,
    authorization_root: Path | None = None,
) -> str:
    """Validate a root/MDM-owned, short-lived, user-bound removal authorization."""

    resolved_root = authorization_root or default_machine_paths().state_root / "removal-authorizations"
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("mdm_removal_authorization_consumed_or_missing") from exc
    if not resolved.is_relative_to(resolved_root.resolve()) or not resolved.is_file():
        raise ValueError("mdm_removal_authorization_wrong_scope")
    metadata = resolved.stat()
    if metadata.st_size > 16 * 1024:
        raise ValueError("mdm_removal_authorization_invalid")
    if platform.system() != "Windows" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise ValueError("mdm_removal_authorization_untrusted_owner")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("mdm_removal_authorization_invalid")
    if payload.get("operation") != "deactivate" or payload.get("user") != user:
        raise ValueError("mdm_removal_authorization_wrong_scope")
    if payload.get("home") != str(home):
        raise ValueError("mdm_removal_authorization_wrong_scope")
    nonce = payload.get("nonce")
    issued_raw = payload.get("issuedAt")
    expires_raw = payload.get("expiresAt")
    if not all(isinstance(value, str) and value for value in (nonce, issued_raw, expires_raw)):
        raise ValueError("mdm_removal_authorization_invalid")
    try:
        issued = datetime.fromisoformat(str(issued_raw))
        expires = datetime.fromisoformat(str(expires_raw))
    except ValueError as exc:
        raise ValueError("mdm_removal_authorization_invalid") from exc
    now = datetime.now(timezone.utc)
    if issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= now:
        raise ValueError("mdm_removal_authorization_expired")
    if (expires - issued).total_seconds() > 300 or (now - issued).total_seconds() > 300:
        raise ValueError("mdm_removal_authorization_expired")
    fingerprint = hashlib.sha256(resolved.read_bytes()).hexdigest()
    try:
        resolved.unlink()
    except OSError as exc:
        raise PermissionError("mdm_removal_authorization_not_consumable") from exc
    return fingerprint


@contextmanager
def _activation_lock(guard_home: Path) -> Iterator[None]:
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = guard_home / "mdm-activation.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if platform.system() == "Windows":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except (BlockingIOError, OSError) as exc:
        raise RuntimeError("mdm_activation_in_progress") from exc
    finally:
        os.close(descriptor)


def _load_trusted_keys(path: Path) -> dict[str, bytes]:
    trusted_keys: dict[str, bytes] = {}
    if not path.is_file():
        return trusted_keys
    try:
        raw_keys = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return trusted_keys
    if not isinstance(raw_keys, dict):
        return trusted_keys
    for key_id, value in raw_keys.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            continue
        try:
            trusted_keys[key_id] = base64.b64decode(value, validate=True)
        except ValueError:
            continue
    return trusted_keys


def machine_status(
    *, machine_root: Path | None = None, policy_path: Path | None = None, allow_unsigned: bool = False
) -> dict[str, object]:
    paths = default_machine_paths()
    runtime_root = (machine_root or paths.runtime_root).resolve()
    manifest_path = runtime_root / "release-manifest.json"
    trusted_keys_path = runtime_root / "release-trusted-keys.json"
    trusted_keys = _load_trusted_keys(trusted_keys_path)
    expected_platform = {"Darwin": "macos", "Windows": "windows"}.get(platform.system())
    verification = verify_release_manifest(
        manifest_path,
        runtime_root,
        trusted_keys=trusted_keys,
        require_signature=not allow_unsigned,
        expected_platform=expected_platform,
        expected_architecture=platform.machine().lower(),
        expected_owner_uid=0 if machine_root is None and platform.system() != "Windows" else None,
    )
    policy = load_managed_policy(policy_path=policy_path)
    native = (
        verify_native_install(runtime_root)
        if machine_root is None
        else NativeInstallVerification("fixture", "native_check_not_applicable", "fixture", "not-applicable")
    )
    payload = _base("status")
    healthy = (
        verification.healthy and policy.status in {"active", "absent"} and (native.healthy or machine_root is not None)
    )
    if verification.healthy and policy.status == "invalid":
        state = "policy-invalid"
    elif verification.healthy and policy.status == "inaccessible":
        state = "degraded"
    elif verification.healthy and not native.healthy and machine_root is None:
        state = native.status
    elif healthy:
        state = "protected"
    else:
        state = verification.status
    reason_codes = [
        code for code in (verification.reason_code, policy.reason_code, native.reason_code) if code is not None
    ]
    update_owner = policy.policy.install_owner if policy.policy is not None else "user"
    if policy.policy is None and policy.status in {"invalid", "inaccessible", "tampered"}:
        update_owner = "mdm"
    payload.update(
        {
            "scope": "machine",
            "state": state,
            "healthy": healthy,
            "runtimeRoot": str(runtime_root),
            "manifest": verification.to_public_dict(),
            "nativeInstall": native.to_dict(),
            "managedPolicy": policy.to_public_dict(),
            "updateOwner": update_owner,
            "reasonCodes": [] if healthy else reason_codes,
        }
    )
    return payload


def user_status(home: Path) -> dict[str, object]:
    guard_home = home / ".hol-guard"
    payload = _base("status")
    if not guard_home.is_dir():
        payload.update(
            {
                "scope": "user",
                "home": str(home),
                "state": "absent",
                "healthy": False,
                "reasonCodes": ["user_not_activated"],
            }
        )
        return payload
    try:
        store = GuardStore(guard_home)
        installs = store.list_managed_installs()
    except (OSError, ValueError) as exc:
        payload.update(
            {
                "scope": "user",
                "home": str(home),
                "state": "degraded",
                "healthy": False,
                "reasonCodes": ["user_state_unreadable"],
                "detail": str(exc)[:256],
            }
        )
        return payload
    active = [item for item in installs if item.get("active")]
    resolved_command = shutil.which("hol-guard")
    expected_runtime = default_machine_paths().runtime_root.resolve()
    shadowed = False
    if resolved_command is not None:
        try:
            shadowed = not Path(resolved_command).resolve().is_relative_to(expected_runtime)
        except OSError:
            shadowed = True
    healthy = bool(active) and not shadowed
    reason_codes: list[str] = []
    if not active:
        reason_codes.append("no_protected_harnesses")
    if shadowed:
        reason_codes.append("machine_command_shadowed")
    user_state = "protected" if healthy else "activated"
    if shadowed:
        user_state = "repairable"
    payload.update(
        {
            "scope": "user",
            "home": str(home),
            "state": user_state,
            "healthy": healthy,
            "activated": True,
            "harnesses": [str(item.get("harness")) for item in active],
            "commandShadowing": {"detected": shadowed},
            "reasonCodes": reason_codes,
        }
    )
    return payload


def activate_user(home: Path, user: str) -> dict[str, object]:
    guard_home = home / ".hol-guard"
    with _activation_lock(guard_home):
        context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)
        store = GuardStore(guard_home)
        before = {str(item.get("harness")) for item in store.list_managed_installs() if bool(item.get("active"))}
        try:
            result = apply_managed_install("install", None, True, context, store, None, _now())
        except (OSError, RuntimeError, ValueError):
            after = {str(item.get("harness")) for item in store.list_managed_installs() if bool(item.get("active"))}
            for harness in sorted(after - before):
                try:
                    apply_managed_install("uninstall", harness, False, context, store, None, _now())
                except (OSError, RuntimeError, ValueError):
                    continue
            raise
        marker = guard_home / "mdm-activation.json"
        marker.write_text(
            json.dumps({"schemaVersion": MDM_STATUS_SCHEMA_VERSION, "user": user, "activatedAt": _now()}) + "\n",
            encoding="utf-8",
        )
        marker.chmod(stat.S_IRUSR | stat.S_IWUSR)
        _audit(guard_home / "logs" / "mdm-lifecycle.log", operation="activate", status="complete", scope="user")
    payload = _base("activate")
    payload.update({"scope": "user", "home": str(home), "user": user, "changed": True, "result": result})
    return payload


def repair_user(home: Path, user: str | None = None) -> dict[str, object]:
    return activate_user(home, user or getpass.getuser()) | {"operation": "repair"}


def deactivate_user(home: Path, *, authorization_fingerprint: str | None = None) -> dict[str, object]:
    guard_home = home / ".hol-guard"
    with _activation_lock(guard_home):
        context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)
        store = GuardStore(guard_home)
        retired_pids = retire_all_guard_daemons_for_home(guard_home)
        result = apply_managed_install("uninstall", None, True, context, store, None, _now())
        (guard_home / "mdm-activation.json").unlink(missing_ok=True)
        _audit(guard_home / "logs" / "mdm-lifecycle.log", operation="deactivate", status="complete", scope="user")
    payload = _base("deactivate")
    payload.update(
        {
            "scope": "user",
            "home": str(home),
            "changed": True,
            "retiredDaemonCount": len(retired_pids),
            "result": result,
        }
    )
    return payload


__all__ = [
    "activate_user",
    "authorize_deactivation",
    "deactivate_user",
    "machine_status",
    "repair_user",
    "user_status",
    "validate_removal_authorization",
    "validate_user_home",
]
