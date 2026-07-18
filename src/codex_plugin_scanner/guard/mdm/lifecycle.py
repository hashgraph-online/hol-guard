"""Prompt-free per-user activation and machine/user health operations."""

from __future__ import annotations

import getpass
import json
import logging
import os
import platform
import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
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
from .removal import (
    authorize_deactivation,
    record_removal_tombstone,
    validate_removal_authorization,
)


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


@contextmanager
def _activation_lock(guard_home: Path) -> Iterator[None]:
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = guard_home / "mdm-activation.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            if platform.system() == "Windows":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            raise RuntimeError("mdm_activation_in_progress") from exc
        yield
    finally:
        os.close(descriptor)


def machine_status(
    *, machine_root: Path | None = None, policy_path: Path | None = None, allow_unsigned: bool = False
) -> dict[str, object]:
    paths = default_machine_paths()
    runtime_root = (machine_root or paths.runtime_root).resolve()
    manifest_path = runtime_root / "release-manifest.json"
    expected_platform = {"Darwin": "macos", "Windows": "windows"}.get(platform.system())
    policy = load_managed_policy(policy_path=policy_path)
    live_policy = policy.policy if policy.reason_code != "managed_policy_profile_removed_cached" else None
    trust = live_policy.integrity_trust if live_policy is not None else None
    trusted_keys = trust.release_public_keys if trust is not None else {}
    minimum_version = policy.policy.update.minimum_version if policy.policy is not None else None
    native = (
        verify_native_install(
            runtime_root,
            macos_team_id=trust.macos_team_id if trust is not None else None,
            windows_signer_thumbprints=trust.windows_signer_thumbprints if trust is not None else (),
        )
        if machine_root is None
        else NativeInstallVerification("fixture", "native_check_not_applicable", "fixture", "not-applicable")
    )
    verification = verify_release_manifest(
        manifest_path,
        runtime_root,
        trusted_keys=trusted_keys,
        require_signature=not allow_unsigned,
        expected_platform=expected_platform,
        expected_architecture=platform.machine().lower(),
        expected_owner_uid=0 if machine_root is None and platform.system() != "Windows" else None,
        expected_installer_identity=(
            native.package_identity
            if native.healthy
            else {"Darwin": "org.hol.guard", "Windows": "HOLGuardMachine"}.get(platform.system())
        ),
        expected_native_version=native.version if native.healthy else None,
        minimum_version=minimum_version,
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


def deactivate_user(
    home: Path,
    *,
    user: str,
    authorization_file: Path | None = None,
) -> dict[str, object]:
    if authorization_file is None:
        raise PermissionError("mdm_removal_authorization_required")
    paths = default_machine_paths()
    evidence = validate_removal_authorization(
        authorization_file,
        home=home,
        user=user,
    )
    _ = record_removal_tombstone(evidence, status="started", machine_paths=paths)
    guard_home = home / ".hol-guard"
    try:
        with _activation_lock(guard_home):
            context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)
            store = GuardStore(guard_home)
            retired_pids = retire_all_guard_daemons_for_home(guard_home)
            result = apply_managed_install("uninstall", None, True, context, store, None, _now())
            (guard_home / "mdm-activation.json").unlink(missing_ok=True)
            _audit(guard_home / "logs" / "mdm-lifecycle.log", operation="deactivate", status="complete", scope="user")
    except (OSError, RuntimeError, ValueError):
        _ = record_removal_tombstone(evidence, status="failed", machine_paths=paths)
        raise
    _ = record_removal_tombstone(evidence, status="completed", machine_paths=paths)
    payload = _base("deactivate")
    payload.update(
        {
            "scope": "user",
            "home": str(home),
            "changed": True,
            "retiredDaemonCount": len(retired_pids),
            "authorizationFingerprint": evidence.fingerprint,
            "machineInstallationId": evidence.machine_installation_id,
            "installationGeneration": evidence.installation_generation,
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
