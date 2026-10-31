"""Fail-honest, read-only local integrity snapshot construction.

Every probe runs here. The native runtime composes the snapshot from their
results: the components, reason codes, assurance level and remediation class.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from ...version import __version__
from .acl import OwnershipAclVerification, verify_protected_ownership_and_acl
from .continuity import ContinuityVerification, verify_installation_continuity
from .contracts import (
    LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
    KeyProtectionStatus,
    LocalIntegritySnapshot,
    MachinePaths,
    ManagedPolicyState,
    SupervisorStatus,
    default_machine_paths,
)
from .device_key import verify_machine_device_key
from .harness_coverage import verify_harness_coverage
from .manifest import ManifestVerification, verify_release_manifest
from .native import NativeInstallVerification, verify_native_install
from .policy import load_managed_policy
from .supervisor import machine_executable, verify_machine_supervisor

INTEGRITY_SNAPSHOT_FEATURE = "native-integrity-snapshot-v1"
INTEGRITY_SNAPSHOT_COMMAND = "integrity-snapshot"
INTEGRITY_SNAPSHOT_SCHEMA = "integrity-snapshot.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 64 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_file_hash(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _verify_manifest(
    paths: MachinePaths,
    native: NativeInstallVerification,
    minimum_version: str | None,
    trusted_public_keys: dict[str, bytes],
) -> ManifestVerification:
    try:
        return verify_release_manifest(
            paths.manifest_path,
            paths.runtime_root,
            trusted_keys=trusted_public_keys,
            expected_platform={"Darwin": "macos", "Windows": "windows"}.get(platform.system()),
            expected_architecture=platform.machine().lower(),
            expected_owner_uid=0 if platform.system() != "Windows" else None,
            expected_installer_identity=(
                native.package_identity
                if native.healthy
                else {"Darwin": "org.hol.guard", "Windows": "HOLGuardMachine"}.get(platform.system())
            ),
            expected_native_version=native.version if native.healthy else None,
            minimum_version=minimum_version,
        )
    except Exception:
        return ManifestVerification("unknown", "release_manifest_probe_failed")


def _verify_native(
    runtime_root: Path,
    *,
    macos_team_id: str | None,
    windows_signer_thumbprints: tuple[str, ...],
) -> NativeInstallVerification:
    try:
        return verify_native_install(
            runtime_root,
            macos_team_id=macos_team_id,
            windows_signer_thumbprints=windows_signer_thumbprints,
        )
    except Exception:
        return NativeInstallVerification("unknown", "native_install_probe_failed", "unknown", "unknown")


def _load_policy() -> ManagedPolicyState:
    try:
        return load_managed_policy(write_cache=False)
    except Exception:
        return ManagedPolicyState("inaccessible", "native", reason_code="managed_policy_probe_failed")


def _verify_ownership_acl(paths: MachinePaths) -> OwnershipAclVerification:
    try:
        return verify_protected_ownership_and_acl(paths)
    except Exception:
        return OwnershipAclVerification("unknown", "ownership_acl_probe_failed", ())


def _verify_supervisor(paths: MachinePaths) -> SupervisorStatus:
    try:
        return verify_machine_supervisor(paths)
    except Exception:
        return SupervisorStatus("unknown", "supervisor_probe_failed")


def _verify_device_key(paths: MachinePaths) -> KeyProtectionStatus:
    try:
        return verify_machine_device_key(paths)
    except Exception:
        return KeyProtectionStatus("unknown", "unknown", "device_key_probe_failed")


def _verify_continuity(paths: MachinePaths) -> ContinuityVerification:
    try:
        return verify_installation_continuity(paths)
    except Exception:
        return ContinuityVerification("unknown", "installation_identity_probe_failed", "lease_continuity_probe_failed")


def _command_shadowing(paths: MachinePaths) -> dict[str, str]:
    try:
        resolved = shutil.which("hol-guard")
        if resolved is None:
            return {"state": "healthy", "reason_code": "command_shadowing_absent"}
        command_path = Path(resolved).resolve(strict=True)
        expected_executable = machine_executable(paths, platform.system()).resolve(strict=False)
        if command_path == expected_executable:
            return {"state": "healthy", "reason_code": "command_shadowing_trusted"}
        return {"state": "tampered", "reason_code": "command_shadowing_detected"}
    except (OSError, RuntimeError):
        return {"state": "unknown", "reason_code": "command_shadowing_probe_failed"}


def _native_snapshot(request: dict[str, object]) -> LocalIntegritySnapshot:
    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    output = None
    if (
        status.available
        and status.compatible
        and status.identity is not None
        and status.capabilities is not None
        and INTEGRITY_SNAPSHOT_FEATURE in status.capabilities.features
    ):
        output = _run_native_process(
            status.identity.path,
            (INTEGRITY_SNAPSHOT_COMMAND, "--stdin"),
            input_text=json.dumps({"schema": INTEGRITY_SNAPSHOT_SCHEMA, **request}, sort_keys=True),
            timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
            output_limit=_OUTPUT_LIMIT_BYTES,
        )
    try:
        snapshot = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        snapshot = None
    if (
        not isinstance(snapshot, dict)
        or cast(dict[str, object], snapshot).get("schemaVersion") != LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION
    ):
        # Evidence nothing could compose is never reported as a snapshot.
        raise OSError("integrity_snapshot_native_unavailable")
    return cast(LocalIntegritySnapshot, cast(object, snapshot))


def machine_integrity_snapshot() -> LocalIntegritySnapshot:
    """Return bounded machine evidence without trusting environment path overrides."""

    paths = default_machine_paths()
    policy = _load_policy()
    minimum_version = policy.policy.update.minimum_version if policy.policy is not None else None
    live_policy = policy.policy if policy.reason_code != "managed_policy_profile_removed_cached" else None
    trust = live_policy.integrity_trust if live_policy is not None else None
    native = _verify_native(
        paths.runtime_root,
        macos_team_id=trust.macos_team_id if trust is not None else None,
        windows_signer_thumbprints=trust.windows_signer_thumbprints if trust is not None else (),
    )
    manifest = _verify_manifest(
        paths,
        native,
        minimum_version,
        trust.release_public_keys if trust is not None else {},
    )
    return _native_snapshot(
        {
            "generated_at": _now(),
            "platform": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "fallback_version": __version__,
            "manifest_hash": _bounded_file_hash(paths.manifest_path),
            "policy": {
                "status": policy.status,
                "reason_code": policy.reason_code,
                "install_owner": policy.policy.install_owner if policy.policy is not None else None,
                "content_hash": policy.policy.content_hash if policy.policy is not None else None,
            },
            "native": asdict(native),
            "manifest": asdict(manifest),
            "acl": asdict(_verify_ownership_acl(paths)),
            "supervisor": asdict(_verify_supervisor(paths)),
            "device_key": asdict(_verify_device_key(paths)),
            "continuity": asdict(_verify_continuity(paths)),
            "harness": asdict(verify_harness_coverage(paths, policy)),
            "command_shadowing": _command_shadowing(paths),
        }
    )


__all__ = ["machine_integrity_snapshot"]
