"""Fail-honest ownership and ACL verification for machine protection surfaces.

This module does the platform I/O: the macOS path-chain walk with ``lstat`` and
``ls -lde``, and the pinned PowerShell probe on Windows. The native runtime
lists the Windows surfaces to probe, classifies the probe's rows and folds the
per-surface results into one verdict. Without the runtime no surface reports
health.
"""

from __future__ import annotations

import base64
import json
import ntpath
import os
import platform
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .contracts import MachinePaths
from .windows_support import windows_directory

AclState = Literal["healthy", "absent", "tampered", "unsupported", "unknown"]

_MAX_ACL_OUTPUT_BYTES = 1024 * 1024
_MUTATING_POSIX_ACL_RIGHTS = {
    "add_file",
    "add_subdirectory",
    "append",
    "chown",
    "delete",
    "delete_child",
    "write",
    "writeattr",
    "writeextattr",
    "writesecurity",
}
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


@dataclass(frozen=True, slots=True)
class _MacosAclCacheEntry:
    reason_code: str | None
    fingerprint: tuple[int, ...] | None


def _probe_failed(surfaces: tuple[AclSurfaceResult, ...] | None = None) -> OwnershipAclVerification:
    return OwnershipAclVerification(
        "unknown",
        "ownership_acl_probe_failed",
        surfaces or (AclSurfaceResult("platform", "unknown", "ownership_acl_probe_failed"),),
    )


def _native_answer(request: dict[str, object]) -> dict[str, object] | None:
    """The runtime's answer to one ownership-acl request, or ``None`` when it cannot answer."""

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or OWNERSHIP_ACL_FEATURE not in status.capabilities.features
    ):
        return None
    output = _run_native_process(
        status.identity.path,
        (OWNERSHIP_ACL_COMMAND, "--stdin"),
        input_text=json.dumps({"schema": OWNERSHIP_ACL_SCHEMA, **request}, sort_keys=True),
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
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


def _native_verdict(request: dict[str, object]) -> OwnershipAclVerification | None:
    answer = _native_answer(request)
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


def _aggregate(surfaces: list[AclSurfaceResult]) -> OwnershipAclVerification:
    verdict = _native_verdict(
        {
            "op": "aggregate",
            "surfaces": [
                {"name": surface.name, "state": surface.state, "reason_code": surface.reason_code}
                for surface in surfaces
            ],
        }
    )
    # Results nothing could fold never report health.
    return verdict or _probe_failed(tuple(surfaces))


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


def _path_chain(path: Path, trust_root: Path) -> tuple[Path, ...]:
    resolved: list[Path] = []
    current = path
    while True:
        resolved.append(current)
        if current == trust_root:
            return tuple(reversed(resolved))
        parent = current.parent
        if parent == current or not current.is_relative_to(trust_root):
            raise ValueError("surface escapes trusted root")
        current = parent


def _macos_acl_is_mutable(path: Path) -> bool:
    result = subprocess.run(
        ["/bin/ls", "-lde", str(path)],
        check=False,
        capture_output=True,
        env={"LC_ALL": "C"},
        text=True,
        timeout=5,
    )
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > _MAX_ACL_OUTPUT_BYTES:
        raise OSError("macOS ACL query failed")
    for raw_line in result.stdout.splitlines()[1:]:
        tokens = raw_line.strip().split()
        if not tokens or not tokens[0].rstrip(":").isdigit() or "allow" not in tokens:
            continue
        allow_index = tokens.index("allow")
        if tokens[1].casefold() == "user:root":
            continue
        rights = {right.strip().casefold() for token in tokens[allow_index + 1 :] for right in token.split(",")}
        if rights & _MUTATING_POSIX_ACL_RIGHTS:
            return True
    return False


def _verify_macos_surface(
    surface: _PathSurface,
    *,
    expected_uid: int,
    cache: dict[Path, _MacosAclCacheEntry],
) -> AclSurfaceResult:
    def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_ctime_ns,
        )

    def failure(reason_code: str) -> AclSurfaceResult:
        state: AclState = "absent" if reason_code == "ownership_acl_surface_absent" else "tampered"
        return AclSurfaceResult(surface.name, state, reason_code)

    try:
        chain = _path_chain(surface.path, surface.trust_root)
        for candidate in chain:
            if candidate in cache:
                cached = cache[candidate]
                if cached.reason_code is not None:
                    return failure(cached.reason_code)
                if cached.fingerprint is None or fingerprint(candidate.lstat()) != cached.fingerprint:
                    return AclSurfaceResult(surface.name, "unknown", "ownership_acl_probe_failed")
                continue
            try:
                before = candidate.lstat()
            except FileNotFoundError:
                cache[candidate] = _MacosAclCacheEntry("ownership_acl_surface_absent", None)
                return AclSurfaceResult(surface.name, "absent", "ownership_acl_surface_absent")
            if stat.S_ISLNK(before.st_mode):
                cache[candidate] = _MacosAclCacheEntry("ownership_acl_path_escape", None)
                return AclSurfaceResult(surface.name, "tampered", "ownership_acl_path_escape")
            if before.st_uid != expected_uid:
                cache[candidate] = _MacosAclCacheEntry("ownership_acl_wrong_owner", None)
                return AclSurfaceResult(surface.name, "tampered", "ownership_acl_wrong_owner")
            if before.st_mode & 0o022 or _macos_acl_is_mutable(candidate):
                cache[candidate] = _MacosAclCacheEntry("ownership_acl_standard_user_writable", None)
                return AclSurfaceResult(surface.name, "tampered", "ownership_acl_standard_user_writable")
            after = candidate.lstat()
            if fingerprint(before) != fingerprint(after):
                return AclSurfaceResult(surface.name, "unknown", "ownership_acl_probe_failed")
            cache[candidate] = _MacosAclCacheEntry(None, fingerprint(after))
        for candidate in chain:
            cached = cache[candidate]
            if cached.fingerprint is None or fingerprint(candidate.lstat()) != cached.fingerprint:
                return AclSurfaceResult(surface.name, "unknown", "ownership_acl_probe_failed")
        final_metadata = surface.path.lstat()
        final_cached = cache[surface.path]
        if final_cached.fingerprint is None or fingerprint(final_metadata) != final_cached.fingerprint:
            return AclSurfaceResult(surface.name, "unknown", "ownership_acl_probe_failed")
        expected_type = (
            stat.S_ISDIR(final_metadata.st_mode) if surface.directory else stat.S_ISREG(final_metadata.st_mode)
        )
        if not expected_type:
            return AclSurfaceResult(surface.name, "tampered", "ownership_acl_path_escape")
        return AclSurfaceResult(surface.name, "healthy", "ownership_acl_valid")
    except (OSError, subprocess.SubprocessError, ValueError):
        return AclSurfaceResult(surface.name, "unknown", "ownership_acl_probe_failed")


_windows_directory = windows_directory


def _windows_paths(paths: MachinePaths) -> dict[str, str]:
    return {
        "runtime_root": str(paths.runtime_root),
        "manifest_path": str(paths.manifest_path),
        "state_root": str(paths.state_root),
        "log_root": str(paths.log_root),
    }


def _windows_surface_payload(paths: MachinePaths) -> list[dict[str, str | bool]]:
    answer = _native_answer({"op": "windows-payload", "windows_paths": _windows_paths(paths)})
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


def _run_windows_acl_probe(paths: MachinePaths) -> object:
    return _run_windows_acl_payload(_windows_surface_payload(paths))


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
        selected = macos_surfaces or _macos_surfaces(paths)
        cache: dict[Path, _MacosAclCacheEntry] = {}
        return _aggregate(
            [_verify_macos_surface(surface, expected_uid=expected_posix_uid, cache=cache) for surface in selected]
        )
    if resolved_system == "Windows":
        try:
            rows = _run_windows_acl_probe(paths)
        except (OSError, subprocess.SubprocessError, ValueError):
            return _probe_failed()
        verdict = _native_verdict({"op": "windows-verify", "windows_paths": _windows_paths(paths), "rows": rows})
        return verdict or _probe_failed()
    return OwnershipAclVerification(
        "unsupported",
        "ownership_acl_platform_unsupported",
        (AclSurfaceResult("platform", "unsupported", "ownership_acl_platform_unsupported"),),
    )


__all__ = ["AclSurfaceResult", "OwnershipAclVerification", "verify_protected_ownership_and_acl"]
