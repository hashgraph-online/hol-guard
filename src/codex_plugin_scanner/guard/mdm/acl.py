"""Fail-honest ownership and ACL verification for machine protection surfaces."""

from __future__ import annotations

import base64
import json
import ntpath
import os
import platform
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .contracts import MachinePaths

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
_WINDOWS_PRIVILEGED_OWNER_SIDS = {
    "S-1-5-18",  # LocalSystem
    "S-1-5-32-544",  # Builtin Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
}
_WINDOWS_PRIVILEGED_ACE_SIDS = _WINDOWS_PRIVILEGED_OWNER_SIDS | {
    "S-1-3-0",  # Creator Owner resolves to the separately verified privileged owner
    "S-1-3-4",  # Owner Rights resolves to the separately verified privileged owner
}
_WINDOWS_FILE_MUTATION_MASK = 852_310
_WINDOWS_REGISTRY_MUTATION_MASK = 851_974
_WINDOWS_FILE_ANCESTOR_MUTATION_MASK = 852_032
_WINDOWS_REGISTRY_ANCESTOR_MUTATION_MASK = 851_968
_WINDOWS_GENERIC_MUTATION_MASK = 0x50000000
_WINDOWS_ACTIVE_SETUP = (
    r"HKLM:\Software\Microsoft\Active Setup\Installed Components\{AFA2F379-D7A2-4210-91E3-E71E43F1D994}"
)
_WINDOWS_POLICY = r"HKLM:\Software\Policies\HOL\Guard"


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


def _aggregate(surfaces: list[AclSurfaceResult]) -> OwnershipAclVerification:
    priority = (
        "ownership_acl_path_escape",
        "ownership_acl_standard_user_writable",
        "ownership_acl_wrong_owner",
    )
    for reason in priority:
        if any(surface.reason_code == reason for surface in surfaces):
            return OwnershipAclVerification("tampered", reason, tuple(surfaces))
    if any(surface.state == "tampered" for surface in surfaces):
        return OwnershipAclVerification("tampered", "ownership_acl_probe_failed", tuple(surfaces))
    if any(surface.state == "absent" for surface in surfaces):
        return OwnershipAclVerification("absent", "ownership_acl_surface_absent", tuple(surfaces))
    if any(surface.state == "unknown" for surface in surfaces):
        return OwnershipAclVerification("unknown", "ownership_acl_probe_failed", tuple(surfaces))
    if any(surface.state == "unsupported" for surface in surfaces):
        return OwnershipAclVerification("unsupported", "ownership_acl_platform_unsupported", tuple(surfaces))
    return OwnershipAclVerification("healthy", "ownership_acl_valid", tuple(surfaces))


def _macos_surfaces(paths: MachinePaths) -> tuple[_PathSurface, ...]:
    trust_root = Path("/")
    surfaces = [
        _PathSurface("runtime", paths.runtime_root, True, trust_root),
        _PathSurface("manifest", paths.manifest_path, False, trust_root),
        _PathSurface("machineState", paths.state_root, True, trust_root),
        _PathSurface("logs", paths.log_root, True, trust_root),
        _PathSurface(
            "serviceRegistration",
            Path("/Library/LaunchAgents/org.hol.guard.user-activation.plist"),
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
        principal = " ".join(tokens[1:allow_index]).casefold()
        if principal == "user:root":
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


def _windows_directory() -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("windows_system_directory_unavailable")
    return ntpath.normpath(str(buffer.value))


def _windows_filesystem_chain(path: str) -> tuple[str, ...]:
    current = ntpath.normpath(path)
    drive, tail = ntpath.splitdrive(current)
    if not drive or not tail.startswith("\\"):
        raise ValueError("Windows surface is not drive-absolute")
    root = f"{drive}\\"
    chain = [current]
    while current.casefold() != root.casefold():
        parent = ntpath.dirname(current)
        if parent == current or not parent:
            raise ValueError("Windows surface escapes drive root")
        current = parent
        chain.append(current)
    return tuple(reversed(chain))


def _windows_registry_chain(path: str) -> tuple[str, ...]:
    prefix = "HKLM:\\"
    if not path.casefold().startswith(prefix.casefold()):
        raise ValueError("Windows registry surface escapes HKLM")
    segments = [segment for segment in path[len(prefix) :].split("\\") if segment]
    return tuple([prefix, *(prefix + "\\".join(segments[:index]) for index in range(1, len(segments) + 1))])


def _windows_surface_payload(paths: MachinePaths) -> list[dict[str, str | bool]]:
    requested: tuple[tuple[str, str, bool], ...] = (
        ("filesystem", str(paths.runtime_root), True),
        ("filesystem", str(paths.manifest_path), False),
        ("filesystem", str(paths.state_root), True),
        ("filesystem", str(paths.log_root), True),
        ("registry", _WINDOWS_POLICY, True),
        ("registry", _WINDOWS_ACTIVE_SETUP, True),
    )
    payload: list[dict[str, str | bool]] = []
    seen: set[tuple[str, str]] = set()
    for kind, leaf, leaf_container in requested:
        chain = _windows_filesystem_chain(leaf) if kind == "filesystem" else _windows_registry_chain(leaf)
        for index, path in enumerate(chain):
            key = (kind, path.casefold())
            if key in seen:
                if index == len(chain) - 1:
                    existing = next(item for item in payload if item["kind"] == kind and item["path"] == path)
                    existing["leaf"] = True
                continue
            seen.add(key)
            payload.append(
                {
                    "name": f"{kind}-{len(payload):03d}",
                    "path": path,
                    "kind": kind,
                    "expectedContainer": True if index < len(chain) - 1 else leaf_container,
                    "leaf": index == len(chain) - 1,
                }
            )
    return payload


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


def _run_windows_acl_probe(paths: MachinePaths) -> object:
    encoded = base64.b64encode(json.dumps(_windows_surface_payload(paths), separators=(",", ":")).encode()).decode()
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


def _windows_result(row: object) -> AclSurfaceResult:
    if not isinstance(row, dict) or not isinstance(row.get("Name"), str):
        raise ValueError("invalid Windows ACL row")
    name = cast(str, row["Name"])
    if row.get("Exists") is not True:
        return AclSurfaceResult(name, "absent", "ownership_acl_surface_absent")
    if row.get("Truncated") is True:
        return AclSurfaceResult(name, "unknown", "ownership_acl_probe_failed")
    if row.get("NullDacl") is True:
        return AclSurfaceResult(name, "tampered", "ownership_acl_standard_user_writable")
    attributes = row.get("Attributes")
    if not isinstance(attributes, int) or attributes & 0x400:
        return AclSurfaceResult(name, "tampered", "ownership_acl_path_escape")
    kind = row.get("Kind")
    expected_container = row.get("ExpectedContainer")
    leaf = row.get("Leaf")
    if kind not in {"filesystem", "registry"} or not isinstance(expected_container, bool) or not isinstance(leaf, bool):
        raise ValueError("invalid Windows ACL row kind")
    if row.get("Container") is not expected_container:
        return AclSurfaceResult(name, "tampered", "ownership_acl_path_escape")
    owner = row.get("Owner")
    if not isinstance(owner, str) or owner not in _WINDOWS_PRIVILEGED_OWNER_SIDS:
        return AclSurfaceResult(name, "tampered", "ownership_acl_wrong_owner")
    rules = row.get("Rules")
    if not isinstance(rules, list):
        raise ValueError("invalid Windows ACL rules")
    if kind == "registry":
        mutation_mask = _WINDOWS_REGISTRY_MUTATION_MASK if leaf else _WINDOWS_REGISTRY_ANCESTOR_MUTATION_MASK
    else:
        mutation_mask = _WINDOWS_FILE_MUTATION_MASK if leaf else _WINDOWS_FILE_ANCESTOR_MUTATION_MASK
    mutation_mask |= _WINDOWS_GENERIC_MUTATION_MASK
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("invalid Windows ACL rule")
        sid = rule.get("Sid")
        rights = rule.get("Rights")
        access_type = rule.get("Type")
        propagation = rule.get("Propagation")
        propagation_flags = {flag.strip() for flag in propagation.split(",")} if isinstance(propagation, str) else set()
        if (
            not isinstance(sid, str)
            or not isinstance(rights, int)
            or access_type not in {"Allow", "Deny"}
            or not isinstance(propagation, str)
            or not propagation_flags
            or not propagation_flags <= {"None", "InheritOnly", "NoPropagateInherit"}
        ):
            raise ValueError("invalid Windows ACL rule fields")
        if (
            access_type == "Allow"
            and "InheritOnly" not in propagation_flags
            and sid not in _WINDOWS_PRIVILEGED_ACE_SIDS
            and rights & mutation_mask
        ):
            return AclSurfaceResult(name, "tampered", "ownership_acl_standard_user_writable")
    return AclSurfaceResult(name, "healthy", "ownership_acl_valid")


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
            raw = _run_windows_acl_probe(paths)
            rows = raw if isinstance(raw, list) else [raw]
            expected_names = {item["name"] for item in _windows_surface_payload(paths)}
            results = [_windows_result(row) for row in rows]
            if len(results) != len(expected_names) or {result.name for result in results} != expected_names:
                raise ValueError("Windows ACL output is incomplete")
            return _aggregate(results)
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return OwnershipAclVerification(
                "unknown",
                "ownership_acl_probe_failed",
                (AclSurfaceResult("platform", "unknown", "ownership_acl_probe_failed"),),
            )
    return OwnershipAclVerification(
        "unsupported",
        "ownership_acl_platform_unsupported",
        (AclSurfaceResult("platform", "unsupported", "ownership_acl_platform_unsupported"),),
    )


__all__ = ["AclSurfaceResult", "OwnershipAclVerification", "verify_protected_ownership_and_acl"]
