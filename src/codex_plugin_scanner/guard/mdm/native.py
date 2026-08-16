"""Native package identity and publisher-signature verification."""

from __future__ import annotations

import ctypes
import json
import ntpath
import platform
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True, slots=True)
class NativeInstallVerification:
    status: str
    reason_code: str
    package_identity: str
    signature_state: str
    version: str | None = None

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasonCode": self.reason_code,
            "packageIdentity": self.package_identity,
            "signatureState": self.signature_state,
            "version": self.version,
        }


def _validated_version(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        Version(value)
    except InvalidVersion:
        return None
    return value.strip()


def verify_native_install(
    runtime_root: Path,
    *,
    macos_team_id: str | None = None,
    windows_signer_thumbprints: tuple[str, ...] = (),
) -> NativeInstallVerification:
    if platform.system() == "Darwin":
        return _verify_macos(runtime_root, expected_team_id=macos_team_id)
    if platform.system() == "Windows":
        return _verify_windows(runtime_root, expected_thumbprints=windows_signer_thumbprints)
    return NativeInstallVerification("unsupported", "native_platform_unsupported", "unknown", "unsupported")


def _verify_macos(runtime_root: Path, *, expected_team_id: str | None) -> NativeInstallVerification:
    identity = "org.hol.guard"
    if expected_team_id is None:
        return NativeInstallVerification("unknown", "native_publisher_pin_absent", identity, "unverified")
    executable = runtime_root / "hol-guard" / "hol-guard"
    try:
        receipt = subprocess.run(
            ["/usr/sbin/pkgutil", "--pkg-info-plist", identity],
            check=True,
            capture_output=True,
            timeout=5,
        )
        receipt_payload = plistlib.loads(receipt.stdout)
        version = receipt_payload.get("pkg-version") if isinstance(receipt_payload, dict) else None
        signature = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(executable)],
            check=False,
            capture_output=True,
            timeout=10,
        )
        signature_details = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException):
        return NativeInstallVerification("absent", "native_package_receipt_absent", identity, "unknown")
    validated_version = _validated_version(version)
    if validated_version is None:
        return NativeInstallVerification("tampered", "native_package_version_invalid", identity, "invalid")
    team_id = next(
        (
            line.partition("=")[2].strip()
            for line in signature_details.stderr.splitlines()
            if line.startswith("TeamIdentifier=")
        ),
        None,
    )
    if signature.returncode != 0 or signature_details.returncode != 0 or team_id != expected_team_id:
        return NativeInstallVerification(
            "tampered", "native_publisher_signature_invalid", identity, "invalid", validated_version
        )
    return NativeInstallVerification("healthy", "native_install_valid", identity, "valid", validated_version)


def _verify_windows(runtime_root: Path, *, expected_thumbprints: tuple[str, ...]) -> NativeInstallVerification:
    identity = "HOLGuardMachine"
    if not expected_thumbprints:
        return NativeInstallVerification("unknown", "native_publisher_pin_absent", identity, "unverified")
    executable = runtime_root / "hol-guard" / "hol-guard.exe"
    escaped = str(executable).replace("'", "''")
    command = "".join(
        (
            f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';",
            f"$v=(Get-Item -LiteralPath '{escaped}').VersionInfo.ProductVersion;",
            "@{Status=$s.Status.ToString();Thumbprint=if($s.SignerCertificate)",
            "{$s.SignerCertificate.Thumbprint}else{$null};Version=$v}|ConvertTo-Json -Compress",
        )
    )
    try:
        windows_directory = _windows_directory()
        system_directory = ntpath.join(windows_directory, "System32")
        powershell = ntpath.join(system_directory, "WindowsPowerShell", "v1.0", "powershell.exe")
        child_environment = {
            "ComSpec": ntpath.join(system_directory, "cmd.exe"),
            "SystemRoot": windows_directory,
            "WINDIR": windows_directory,
        }
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
            cwd=system_directory,
            env=child_environment,
            text=True,
            timeout=15,
        )
        payload: object = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return NativeInstallVerification("absent", "native_package_identity_absent", identity, "unknown")
    thumbprint = payload.get("Thumbprint") if isinstance(payload, dict) else None
    version = payload.get("Version") if isinstance(payload, dict) else None
    normalized_thumbprint = thumbprint.replace(" ", "").upper() if isinstance(thumbprint, str) else None
    validated_version = _validated_version(version)
    if (
        not isinstance(payload, dict)
        or payload.get("Status") != "Valid"
        or normalized_thumbprint not in expected_thumbprints
        or validated_version is None
    ):
        return NativeInstallVerification("tampered", "native_publisher_signature_invalid", identity, "invalid")
    return NativeInstallVerification("healthy", "native_install_valid", identity, "valid", validated_version)


def _windows_directory() -> str:
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("windows_system_directory_unavailable")
    return ntpath.normpath(str(buffer.value))


__all__ = ["NativeInstallVerification", "verify_native_install"]
