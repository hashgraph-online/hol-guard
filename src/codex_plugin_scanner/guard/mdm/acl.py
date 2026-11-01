"""Fail-honest ownership and ACL verification for machine protection surfaces.

The native runtime walks each macOS surface's path chain with ``lstat`` and
``ls -lde``. On Windows this module runs the pinned PowerShell probe; the
runtime lists the surfaces to probe, classifies the probe's rows and folds the
per-surface results into one verdict. Without the runtime no surface reports
health.
"""

from __future__ import annotations

import base64
import json
import ntpath
import platform
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .contracts import MachinePaths
from .windows_support import windows_directory

AclState = Literal["healthy", "absent", "tampered", "unsupported", "unknown"]

_MAX_ACL_OUTPUT_BYTES = 1024 * 1024
OWNERSHIP_ACL_FEATURE = "native-ownership-acl-v1"
OWNERSHIP_ACL_COMMAND = "ownership-acl"
OWNERSHIP_ACL_SCHEMA = "ownership-acl.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_ACL_STATES: frozenset[str] = frozenset({"healthy", "absent", "tampered", "unsupported", "unknown"})


@dataclass(frozen=True, slots=True)
class AclSurfaceResult:
    name: str
    state: AclState
    reason_code: str

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"


@dataclass(frozen=True, slots=True)
class OwnershipAclVerification:
    status: AclState
    reason_code: str
    surfaces: tuple[AclSurfaceResult, ...]

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"


@dataclass(frozen=True, slots=True)
class _PathSurface:
    name: str
    path: Path
    directory: bool
    trust_root: Path


def _probe_failed(surfaces: tuple[AclSurfaceResult, ...] | None = None) -> OwnershipAclVerification:
    return OwnershipAclVerification(
        "unknown",
        "ownership_acl_probe_failed",
        surfaces or (AclSurfaceResult("platform", "unknown", "ownership_acl_probe_failed"),),
    )


def _native_deadline() -> float:
    """One budget shared by every runtime call made for a single verification."""

    return time.monotonic() + _COMMAND_TIMEOUT_SECONDS


def _native_answer(request: dict[str, object], *, deadline: float) -> dict[str, object] | None:
    """The runtime's answer to one ownership-acl request, or ``None`` when it cannot answer."""

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=min(deadline, time.monotonic() + _STATUS_TIMEOUT_SECONDS))
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or OWNERSHIP_ACL_FEATURE not in status.capabilities.features
    ):
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    output = _run_native_process(
        status.identity.path,
        (OWNERSHIP_ACL_COMMAND, "--stdin"),
        input_text=json.dumps({"schema": OWNERSHIP_ACL_SCHEMA, **request}, sort_keys=True),
        timeout_seconds=remaining,
        output_limit=_MAX_ACL_OUTPUT_BYTES,
    )
    if output is None:
        return None
    try:
        answer = cast(object, json.loads(output))
    except ValueError:
        return None
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        return None
    return cast(dict[str, object], answer)


def _native_verdict(request: dict[str, object], *, deadline: float) -> OwnershipAclVerification | None:
    answer = _native_answer(request, deadline=deadline)
    if answer is None:
        return None
    status = answer.get("status")
    reason_code = answer.get("reason_code")
    rows = answer.get("surfaces")
    if status not in _ACL_STATES or not isinstance(reason_code, str) or not isinstance(rows, list):
        return None
    surfaces: list[AclSurfaceResult] = []
    for row in cast(list[object], rows):
        if not isinstance(row, dict):
            return None
        fields = cast(dict[str, object], row)
        name, state, reason = fields.get("name"), fields.get("state"), fields.get("reason_code")
        if not isinstance(name, str) or state not in _ACL_STATES or not isinstance(reason, str):
            return None
        surfaces.append(AclSurfaceResult(name, cast(AclState, state), reason))
    return OwnershipAclVerification(cast(AclState, status), reason_code, tuple(surfaces))


def _macos_surfaces(paths: MachinePaths) -> tuple[_PathSurface, ...]:
    trust_root = Path("/")
    surfaces = [
        _PathSurface("runtime", paths.runtime_root, True, trust_root),
        _PathSurface("manifest", paths.manifest_path, False, trust_root),
        _PathSurface("machineState", paths.state_root, True, trust_root),
        _PathSurface("deviceKeyMetadata", paths.state_root / "device-key.json", False, trust_root),
        _PathSurface("installationContinuity", paths.state_root / "installation-continuity.json", False, trust_root),
        _PathSurface(
            "installationContinuityLock", paths.state_root / ".installation-continuity.lock", False, trust_root
        ),
        _PathSurface("logs", paths.log_root, True, trust_root),
        _PathSurface(
            "serviceRegistration",
            Path("/Library/LaunchAgents/org.hol.guard.user-activation.plist"),
            False,
            trust_root,
        ),
        _PathSurface(
            "machineHealthRegistration",
            Path("/Library/LaunchDaemons/org.hol.guard.machine-health.plist"),
            False,
            trust_root,
        ),
    ]
    if paths.policy_path is not None:
        surfaces.append(_PathSurface("managedPolicy", paths.policy_path, False, trust_root))
    return tuple(surfaces)


def _macos_request(surfaces: tuple[_PathSurface, ...], expected_uid: int) -> dict[str, object]:
    return {
        "op": "macos-verify",
        "macos_surfaces": [
            {
                "name": surface.name,
                "path": str(surface.path),
                "directory": surface.directory,
                "trust_root": str(surface.trust_root),
            }
            for surface in surfaces
        ],
        "expected_uid": expected_uid,
    }


_windows_directory = windows_directory


def _windows_paths(paths: MachinePaths) -> dict[str, str]:
    return {
        "runtime_root": str(paths.runtime_root),
        "manifest_path": str(paths.manifest_path),
        "state_root": str(paths.state_root),
        "log_root": str(paths.log_root),
    }


def _windows_surface_payload(paths: MachinePaths, *, deadline: float) -> list[dict[str, str | bool]]:
    answer = _native_answer({"op": "windows-payload", "windows_paths": _windows_paths(paths)}, deadline=deadline)
    payload = None if answer is None else answer.get("payload")
    if not isinstance(payload, list):
        raise OSError("ownership_acl_native_unavailable")
    return cast(list[dict[str, str | bool]], payload)


def _windows_acl_script(encoded_items: str) -> str:
    return (
        "$ErrorActionPreference='Stop';"
        f"$items=ConvertFrom-Json([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_items}')));"
        "$out=@();foreach($item in $items){"
        "if(-not(Test-Path -LiteralPath $item.path)){$out+=@{Name=$item.name;Kind=$item.kind;"
        "ExpectedContainer=$item.expectedContainer;Leaf=$item.leaf;Exists=$false};continue};"
        "$acl=Get-Acl -LiteralPath $item.path;"
        "$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;"
        "$rawRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|"
        "Select-Object -First 257);"
        "$truncated=$rawRules.Count -gt 256;"
        "$rules=@($rawRules|Select-Object -First 256|ForEach-Object{"
        "$rights=if($item.kind -eq 'registry'){[int64]$_.RegistryRights}else{[int64]$_.FileSystemRights};"
        "@{Sid=$_.IdentityReference.Value;Type=$_.AccessControlType.ToString();Rights=$rights;"
        "Propagation=$_.PropagationFlags.ToString()}});"
        "$raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0);"
        "$target=if($item.kind -eq 'registry'){$null}else{Get-Item -LiteralPath $item.path -Force};"
        "$attributes=if($null -eq $target){0}else{[int64]$target.Attributes};"
        "$container=if($item.kind -eq 'registry'){$true}else{[bool]$target.PSIsContainer};"
        "$out+=@{Name=$item.name;Kind=$item.kind;ExpectedContainer=$item.expectedContainer;Leaf=$item.leaf;"
        "Exists=$true;Owner=$owner;Rules=$rules;Truncated=$truncated;"
        "Attributes=$attributes;Container=$container;NullDacl=($null -eq $raw.DiscretionaryAcl)}};"
        "$out|ConvertTo-Json -Compress -Depth 6"
    )


def _run_windows_acl_payload(payload: list[dict[str, str | bool]]) -> object:
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    windows_directory = _windows_directory()
    system_directory = ntpath.join(windows_directory, "System32")
    powershell = ntpath.join(system_directory, "WindowsPowerShell", "v1.0", "powershell.exe")
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", _windows_acl_script(encoded)],
        check=True,
        capture_output=True,
        cwd=system_directory,
        env={
            "ComSpec": ntpath.join(system_directory, "cmd.exe"),
            "SystemRoot": windows_directory,
            "WINDIR": windows_directory,
        },
        text=True,
        timeout=15,
    )
    if len(result.stdout.encode("utf-8")) > _MAX_ACL_OUTPUT_BYTES:
        raise ValueError("Windows ACL output exceeds limit")
    return json.loads(result.stdout)


def _run_windows_acl_probe(paths: MachinePaths, *, deadline: float) -> object:
    return _run_windows_acl_payload(_windows_surface_payload(paths, deadline=deadline))


def verify_protected_ownership_and_acl(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
    expected_posix_uid: int = 0,
    macos_surfaces: tuple[_PathSurface, ...] | None = None,
) -> OwnershipAclVerification:
    """Verify protected surfaces without trusting environment path overrides."""

    resolved_system = system_name or platform.system()
    if resolved_system == "Darwin":
        verdict = _native_verdict(
            _macos_request(macos_surfaces or _macos_surfaces(paths), expected_posix_uid),
            deadline=_native_deadline(),
        )
        return verdict or _probe_failed()
    if resolved_system == "Windows":
        deadline = _native_deadline()
        try:
            rows = _run_windows_acl_probe(paths, deadline=deadline)
        except (OSError, subprocess.SubprocessError, ValueError):
            return _probe_failed()
        verdict = _native_verdict(
            {"op": "windows-verify", "windows_paths": _windows_paths(paths), "rows": rows}, deadline=deadline
        )
        return verdict or _probe_failed()
    return OwnershipAclVerification(
        "unsupported",
        "ownership_acl_platform_unsupported",
        (AclSurfaceResult("platform", "unsupported", "ownership_acl_platform_unsupported"),),
    )


__all__ = ["AclSurfaceResult", "OwnershipAclVerification", "verify_protected_ownership_and_acl"]
