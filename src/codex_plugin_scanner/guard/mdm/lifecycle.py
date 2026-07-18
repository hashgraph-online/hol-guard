"""Prompt-free per-user activation and machine/user health operations."""

from __future__ import annotations

import getpass
import json
import logging
import os
import platform
import secrets
import shutil
import stat
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import cast

from ..adapters.base import HarnessContext
from ..cli.install_commands import apply_managed_install
from ..daemon.manager import retire_all_guard_daemons_for_home
from ..store import GuardStore
from .contracts import MDM_STATUS_SCHEMA_VERSION, default_machine_paths
from .harness_coverage import register_user_harnesses, unregister_user_harnesses
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


def validate_user_home(home: str, user: str | None = None, *, require_user_context: bool = True) -> Path:
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
        if require_user_context and os.geteuid() != account.pw_uid:
            raise ValueError("mdm_user_context_mismatch")
    elif user is not None and require_user_context and getpass.getuser().casefold() != user.casefold():
        raise ValueError("mdm_user_context_mismatch")
    return resolved


@contextmanager
def _activation_lock(guard_home: Path) -> Generator[None, None, None]:
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


_COVERAGE_REQUEST_NAME = "mdm-harness-coverage-request.json"
_COVERAGE_REQUEST_SCHEMA = "hol-guard-harness-coverage-request.v1"
_MAX_COVERAGE_REQUEST_BYTES = 256 * 1024


def _coverage_request_path(home: Path) -> Path:
    return home / ".hol-guard" / _COVERAGE_REQUEST_NAME


def _write_coverage_request(home: Path, installs: list[dict[str, object]]) -> None:
    target = _coverage_request_path(home)
    payload = (
        json.dumps(
            {"schemaVersion": _COVERAGE_REQUEST_SCHEMA, "installs": installs},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if len(payload) > _MAX_COVERAGE_REQUEST_BYTES:
        raise ValueError("harness_coverage_request_capacity_exceeded")
    temporary = target.parent / f".{_COVERAGE_REQUEST_NAME}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _read_coverage_request(home: Path) -> list[dict[str, object]]:
    guard_home = home / ".hol-guard"
    target = _coverage_request_path(home)
    home_metadata = home.stat()
    try:
        guard_metadata = guard_home.lstat()
        target_metadata = target.lstat()
    except FileNotFoundError as exc:
        raise ValueError("harness_coverage_request_absent") from exc
    if (
        not stat.S_ISDIR(guard_metadata.st_mode)
        or stat.S_ISLNK(guard_metadata.st_mode)
        or guard_metadata.st_uid != home_metadata.st_uid
        or guard_metadata.st_mode & 0o022
        or not stat.S_ISREG(target_metadata.st_mode)
        or stat.S_ISLNK(target_metadata.st_mode)
        or target_metadata.st_uid != home_metadata.st_uid
        or target_metadata.st_mode & 0o077
        or target_metadata.st_size > _MAX_COVERAGE_REQUEST_BYTES
    ):
        raise PermissionError("harness_coverage_request_acl_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > _MAX_COVERAGE_REQUEST_BYTES
            or (opened.st_dev, opened.st_ino) != (target_metadata.st_dev, target_metadata.st_ino)
        ):
            raise ValueError("harness_coverage_request_invalid")
        payload = os.read(descriptor, _MAX_COVERAGE_REQUEST_BYTES + 1)
    finally:
        os.close(descriptor)
    final = target.lstat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if not stat.S_ISREG(final.st_mode) or any(
        len({getattr(target_metadata, field), getattr(opened, field), getattr(final, field)}) != 1
        for field in stable_fields
    ):
        raise ValueError("harness_coverage_request_changed")
    if len(payload) > _MAX_COVERAGE_REQUEST_BYTES:
        raise ValueError("harness_coverage_request_capacity_exceeded")
    parsed = cast(object, json.loads(payload))
    if not isinstance(parsed, dict):
        raise ValueError("harness_coverage_request_invalid")
    request = cast(dict[str, object], parsed)
    if set(request) != {"schemaVersion", "installs"}:
        raise ValueError("harness_coverage_request_invalid")
    installs = request.get("installs")
    if request.get("schemaVersion") != _COVERAGE_REQUEST_SCHEMA or not isinstance(installs, list):
        raise ValueError("harness_coverage_request_invalid")
    install_items = cast(list[object], installs)
    if any(not isinstance(item, dict) for item in install_items):
        raise ValueError("harness_coverage_request_invalid")
    return [cast(dict[str, object], item) for item in install_items]


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
        marker = guard_home / "mdm-activation.json"
        request = _coverage_request_path(home)
        try:
            result = apply_managed_install("install", None, True, context, store, None, _now())
            _ = marker.write_text(
                json.dumps({"schemaVersion": MDM_STATUS_SCHEMA_VERSION, "user": user, "activatedAt": _now()}) + "\n",
                encoding="utf-8",
            )
            marker.chmod(stat.S_IRUSR | stat.S_IWUSR)
            _write_coverage_request(home, store.list_managed_installs())
            _audit(guard_home / "logs" / "mdm-lifecycle.log", operation="activate", status="complete", scope="user")
        except (OSError, RuntimeError, ValueError):
            request.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            after = {str(item.get("harness")) for item in store.list_managed_installs() if bool(item.get("active"))}
            for harness in sorted(after - before):
                try:
                    _ = apply_managed_install("uninstall", harness, False, context, store, None, _now())
                except (OSError, RuntimeError, ValueError):
                    continue
            raise
    payload = _base("activate")
    payload.update({"scope": "user", "home": str(home), "user": user, "changed": True, "result": result})
    return payload


def repair_user(home: Path, user: str | None = None) -> dict[str, object]:
    return activate_user(home, user or getpass.getuser()) | {"operation": "repair"}


def register_user_coverage(home: Path, user: str) -> dict[str, object]:
    managed_policy = load_managed_policy()
    if managed_policy.policy is None or managed_policy.policy.install_owner != "mdm":
        raise PermissionError("harness_coverage_managed_policy_required")
    marker = home / ".hol-guard" / "mdm-activation.json"
    try:
        marker_metadata = marker.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("harness_coverage_activation_incomplete") from exc
    if (
        not stat.S_ISREG(marker_metadata.st_mode)
        or stat.S_ISLNK(marker_metadata.st_mode)
        or marker_metadata.st_uid != home.stat().st_uid
        or marker_metadata.st_mode & 0o077
    ):
        raise RuntimeError("harness_coverage_activation_incomplete")
    paths = default_machine_paths()
    installs = _read_coverage_request(home)
    register_user_harnesses(paths, home, installs)
    _audit(
        paths.log_root / "mdm-lifecycle.log", operation="harness-coverage-register", status="complete", scope="machine"
    )
    payload = _base("harness-coverage-register")
    payload.update({"scope": "machine", "user": user, "changed": True})
    return payload


def unregister_user_coverage(home: Path, user: str) -> dict[str, object]:
    guard_home = home / ".hol-guard"
    request = _coverage_request_path(home)
    marker = guard_home / "mdm-activation.json"
    if request.exists() or request.is_symlink() or marker.exists() or marker.is_symlink():
        raise RuntimeError("harness_coverage_deactivation_incomplete")
    paths = default_machine_paths()
    unregister_user_harnesses(paths, home)
    _audit(
        paths.log_root / "mdm-lifecycle.log",
        operation="harness-coverage-unregister",
        status="complete",
        scope="machine",
    )
    payload = _base("harness-coverage-unregister")
    payload.update({"scope": "machine", "user": user, "changed": True})
    return payload


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
            _coverage_request_path(home).unlink(missing_ok=True)
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
    "register_user_coverage",
    "repair_user",
    "unregister_user_coverage",
    "user_status",
    "validate_removal_authorization",
    "validate_user_home",
]
