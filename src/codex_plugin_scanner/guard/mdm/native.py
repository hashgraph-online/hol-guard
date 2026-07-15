"""Native package identity and publisher-signature verification."""

from __future__ import annotations

import json
import platform
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


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


def verify_native_install(runtime_root: Path) -> NativeInstallVerification:
    if platform.system() == "Darwin":
        return _verify_macos(runtime_root)
    if platform.system() == "Windows":
        return _verify_windows(runtime_root)
    return NativeInstallVerification("unsupported", "native_platform_unsupported", "unknown", "unsupported")


def _verify_macos(runtime_root: Path) -> NativeInstallVerification:
    identity = "org.hol.guard"
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
    except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException):
        return NativeInstallVerification("absent", "native_package_receipt_absent", identity, "unknown")
    if signature.returncode != 0:
        return NativeInstallVerification(
            "tampered", "native_publisher_signature_invalid", identity, "invalid", str(version) if version else None
        )
    return NativeInstallVerification(
        "healthy", "native_install_valid", identity, "valid", str(version) if version else None
    )


def _verify_windows(runtime_root: Path) -> NativeInstallVerification:
    identity = "HOLGuardMachine"
    executable = runtime_root / "hol-guard" / "hol-guard.exe"
    escaped = str(executable).replace("'", "''")
    command = (
        f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';"
        "@{Status=$s.Status.ToString();Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null}}"
        "|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        payload: object = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return NativeInstallVerification("absent", "native_package_identity_absent", identity, "unknown")
    if not isinstance(payload, dict) or payload.get("Status") != "Valid" or not payload.get("Signer"):
        return NativeInstallVerification("tampered", "native_publisher_signature_invalid", identity, "invalid")
    return NativeInstallVerification("healthy", "native_install_valid", identity, "valid")


__all__ = ["NativeInstallVerification", "verify_native_install"]
