"""Bounded execution contract for platform-native device-key helpers."""

from __future__ import annotations

import base64
import ctypes
import json
import ntpath
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Literal, cast

from cryptography.hazmat.primitives.asymmetric import utils

from .contracts import KeyProtectionLevel, MachinePaths

_MAX_HELPER_OUTPUT_BYTES = 16 * 1024
_MAX_HELPER_STDERR_BYTES = 4096
_MAX_HEALTH_LEASE_CLAIMS_BYTES = 4096
_HELPER_TIMEOUT_SECONDS = 15
_SYSTEM_SID = "S-1-5-18"
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_HEALTH_LEASE_KEYS = {
    "deviceId",
    "installationGeneration",
    "issuedAt",
    "leaseExpiresAt",
    "machineInstallationId",
    "previousLeaseDigest",
    "previousLeaseKeyId",
    "schemaVersion",
    "sequence",
    "signingKeyId",
    "snapshotDigest",
    "snapshotSchemaVersion",
    "workspaceId",
}
_HEALTH_KEY_REGISTRATION_KEYS = {
    "algorithm",
    "deviceId",
    "installationGeneration",
    "keyId",
    "machineInstallationId",
    "previousInstallationGeneration",
    "publicKeySpki",
    "registeredAt",
    "schemaVersion",
    "workspaceId",
}


@dataclass(frozen=True, slots=True)
class NativeKeyEvidence:
    state: Literal["active", "absent", "unknown", "tampered"]
    protection_level: KeyProtectionLevel
    public_key_x963: bytes | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class NativeHealthLeaseSignature:
    signature: bytes
    algorithm: Literal["ecdsa-p256-sha256"] = "ecdsa-p256-sha256"
    encoding: Literal["asn1-der"] = "asn1-der"


def _validated_canonical_health_lease_claims(claims: bytes) -> str:
    if not claims or len(claims) > _MAX_HEALTH_LEASE_CLAIMS_BYTES:
        raise ValueError("health_lease_claims_invalid")
    try:
        text = claims.decode("utf-8")
        decoded = cast(object, json.loads(text))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health_lease_claims_invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("health_lease_claims_invalid")
    payload = cast(dict[str, object], decoded)
    if set(payload) != _HEALTH_LEASE_KEYS:
        raise ValueError("health_lease_claims_invalid")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != text:
        raise ValueError("health_lease_claims_invalid")
    from .health_lease_contract import HealthLeaseClaims

    try:
        HealthLeaseClaims.parse(payload)
    except ValueError as exc:
        raise ValueError("health_lease_claims_invalid") from exc
    return text


def _validated_canonical_protection_lease(unsigned_lease: bytes) -> str:
    if not unsigned_lease or len(unsigned_lease) > _MAX_HEALTH_LEASE_CLAIMS_BYTES:
        raise ValueError("health_lease_claims_invalid")
    try:
        text = unsigned_lease.decode("utf-8")
        decoded = cast(object, json.loads(text))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health_lease_claims_invalid") from exc
    if not isinstance(decoded, dict) or set(decoded) != {"claims", "schemaVersion"}:
        raise ValueError("health_lease_claims_invalid")
    payload = cast(dict[str, object], decoded)
    if payload.get("schemaVersion") != "protection-lease.v1":
        raise ValueError("health_lease_claims_invalid")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != text:
        raise ValueError("health_lease_claims_invalid")
    from .protection_lease_contract import ProtectionLeaseClaims

    try:
        ProtectionLeaseClaims.parse(payload.get("claims"))
    except ValueError as exc:
        raise ValueError("health_lease_claims_invalid") from exc
    return text


def _validated_canonical_health_key_registration(registration: bytes) -> str:
    if not registration or len(registration) > _MAX_HEALTH_LEASE_CLAIMS_BYTES:
        raise ValueError("health_key_registration_invalid")
    try:
        text = registration.decode("utf-8")
        decoded = cast(object, json.loads(text))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("health_key_registration_invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("health_key_registration_invalid")
    payload = cast(dict[str, object], decoded)
    if (
        set(payload) != _HEALTH_KEY_REGISTRATION_KEYS
        or payload.get("schemaVersion") != "hol-guard-health-key-registration.v1"
        or payload.get("algorithm") != "ecdsa-p256-sha256"
    ):
        raise ValueError("health_key_registration_invalid")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != text:
        raise ValueError("health_key_registration_invalid")
    key_id = payload.get("keyId")
    if not isinstance(key_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", key_id) is None:
        raise ValueError("health_key_registration_invalid")
    return text


def _validated_der_signature(encoded: object) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > 128:
        raise OSError("device_key_probe_failed")
    try:
        signature = base64.b64decode(encoded, validate=True)
        r, s = utils.decode_dss_signature(signature)
    except (ValueError, TypeError) as exc:
        raise OSError("device_key_probe_failed") from exc
    if not 0 < r < _P256_ORDER or not 0 < s < _P256_ORDER or utils.encode_dss_signature(r, s) != signature:
        raise OSError("device_key_probe_failed")
    return signature


def windows_directory() -> str:
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("device_key_probe_failed")
    return ntpath.normpath(str(buffer.value))


def _helper_invocation(
    paths: MachinePaths, verb: str, generation: str, system_name: str
) -> tuple[list[str], dict[str, str], str]:
    if system_name == "Darwin":
        command = [str(paths.runtime_root / "hol-guard-device-key"), verb, generation]
        environment = {
            "HOME": "/var/root",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": "/var/tmp",
        }
        cwd = "/"
    elif system_name == "Windows":
        system_root = windows_directory()
        system_directory = ntpath.join(system_root, "System32")
        command = [
            ntpath.join(system_directory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(paths.runtime_root / "hol-guard" / "device-key-helper.ps1"),
            "-Verb",
            verb,
            "-Generation",
            generation,
        ]
        drive, _ = ntpath.splitdrive(system_root)
        if not drive:
            raise OSError("device_key_probe_failed")
        environment = {
            "ComSpec": ntpath.join(system_directory, "cmd.exe"),
            "SystemDrive": drive,
            "SystemRoot": system_root,
            "WINDIR": system_root,
        }
        cwd = system_directory
    else:
        raise OSError("device_key_platform_unsupported")
    return command, environment, cwd


def run_helper(paths: MachinePaths, verb: str, generation: str, *, system_name: str) -> NativeKeyEvidence:
    if verb not in {"create", "inspect", "delete"}:
        raise ValueError("device_key_request_invalid")
    if system_name not in {"Darwin", "Windows"}:
        return NativeKeyEvidence("unknown", "unavailable", None, "device_key_platform_unsupported")
    command, environment, cwd = _helper_invocation(paths, verb, generation, system_name)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=environment,
        input="",
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
    )
    if (
        len(result.stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > _MAX_HELPER_STDERR_BYTES
    ):
        raise OSError("device_key_probe_failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OSError("device_key_probe_failed") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "ok",
        "state",
        "protectionLevel",
        "publicKeyX963",
        "reasonCode",
    }:
        raise OSError("device_key_probe_failed")
    state = payload.get("state")
    level = payload.get("protectionLevel")
    reason = payload.get("reasonCode")
    public_raw = payload.get("publicKeyX963")
    ok = payload.get("ok")
    if (
        not isinstance(ok, bool)
        or state not in {"active", "absent", "unknown", "tampered"}
        or level not in {"hardware-backed", "os-protected", "unknown"}
        or not isinstance(reason, str)
        or reason
        not in {
            "device_key_active",
            "device_key_absent",
            "device_key_generation_collision",
            "device_key_system_context_required",
            "device_key_request_invalid",
            "device_key_provider_unavailable",
            "device_key_unusable",
            "device_key_probe_failed",
        }
    ):
        raise OSError("device_key_probe_failed")
    public_key: bytes | None = None
    if public_raw is not None:
        if not isinstance(public_raw, str) or len(public_raw) > 256:
            raise OSError("device_key_probe_failed")
        try:
            public_key = base64.b64decode(public_raw, validate=True)
        except ValueError as exc:
            raise OSError("device_key_probe_failed") from exc
        if len(public_key) != 65 or public_key[0] != 4:
            raise OSError("device_key_probe_failed")
    successful = (verb in {"create", "inspect"} and state == "active") or (verb == "delete" and state == "absent")
    if successful:
        expected_return_code = 0
    elif verb == "inspect" and state == "absent":
        expected_return_code = 1
    else:
        expected_return_code = 2
    if result.returncode != expected_return_code or ok != successful:
        raise OSError("device_key_probe_failed")
    return NativeKeyEvidence(
        cast(Literal["active", "absent", "unknown", "tampered"], state),
        cast(KeyProtectionLevel, level),
        public_key,
        reason,
    )


def sign_health_lease(
    paths: MachinePaths, generation: str, canonical_claims: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    claims_text = _validated_canonical_health_lease_claims(canonical_claims)
    command, environment, cwd = _helper_invocation(paths, "sign-health-lease", generation, system_name)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=environment,
        input=claims_text,
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
    )
    if (
        len(result.stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > _MAX_HELPER_STDERR_BYTES
    ):
        raise OSError("device_key_probe_failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OSError("device_key_probe_failed") from exc
    if (
        result.returncode != 0
        or not isinstance(payload, dict)
        or set(payload) != {"ok", "signature", "signatureAlgorithm", "signatureEncoding"}
        or payload.get("ok") is not True
        or payload.get("signatureAlgorithm") != "ecdsa-p256-sha256"
        or payload.get("signatureEncoding") != "asn1-der"
    ):
        raise OSError("device_key_probe_failed")
    return NativeHealthLeaseSignature(_validated_der_signature(payload.get("signature")))


def sign_protection_lease(
    paths: MachinePaths, generation: str, canonical_unsigned_lease: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    lease_text = _validated_canonical_protection_lease(canonical_unsigned_lease)
    command, environment, cwd = _helper_invocation(paths, "sign-protection-lease", generation, system_name)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=environment,
        input=lease_text,
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
    )
    if (
        len(result.stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > _MAX_HELPER_STDERR_BYTES
    ):
        raise OSError("device_key_probe_failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OSError("device_key_probe_failed") from exc
    if (
        result.returncode != 0
        or not isinstance(payload, dict)
        or set(payload) != {"ok", "signature", "signatureAlgorithm", "signatureEncoding"}
        or payload.get("ok") is not True
        or payload.get("signatureAlgorithm") != "ecdsa-p256-sha256"
        or payload.get("signatureEncoding") != "asn1-der"
    ):
        raise OSError("device_key_probe_failed")
    return NativeHealthLeaseSignature(_validated_der_signature(payload.get("signature")))


def sign_health_key_registration(
    paths: MachinePaths, generation: str, canonical_registration: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    registration_text = _validated_canonical_health_key_registration(canonical_registration)
    command, environment, cwd = _helper_invocation(paths, "sign-health-key-registration", generation, system_name)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=environment,
        input=registration_text,
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
    )
    if (
        len(result.stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > _MAX_HELPER_STDERR_BYTES
    ):
        raise OSError("device_key_probe_failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OSError("device_key_probe_failed") from exc
    if (
        result.returncode != 0
        or not isinstance(payload, dict)
        or set(payload) != {"ok", "signature", "signatureAlgorithm", "signatureEncoding"}
        or payload.get("ok") is not True
        or payload.get("signatureAlgorithm") != "ecdsa-p256-sha256"
        or payload.get("signatureEncoding") != "asn1-der"
    ):
        raise OSError("device_key_probe_failed")
    return NativeHealthLeaseSignature(_validated_der_signature(payload.get("signature")))


def windows_current_user_sid() -> str:
    from ctypes import wintypes

    token = wintypes.HANDLE()
    if not ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise OSError("device_key_system_context_required")
    try:
        needed = wintypes.DWORD()
        ctypes.windll.advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not ctypes.windll.advapi32.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError("device_key_system_context_required")
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_string = wintypes.LPWSTR()
        if not ctypes.windll.advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_string)):
            raise OSError("device_key_system_context_required")
        try:
            return str(sid_string.value)
        finally:
            ctypes.windll.kernel32.LocalFree(sid_string)
    finally:
        ctypes.windll.kernel32.CloseHandle(token)


def require_machine_context(system_name: str) -> None:
    if system_name == "Darwin":
        if os.geteuid() != 0:
            raise PermissionError("device_key_system_context_required")
        return
    if system_name == "Windows":
        if windows_current_user_sid() != _SYSTEM_SID:
            raise PermissionError("device_key_system_context_required")
        return
    raise OSError("device_key_platform_unsupported")


__all__ = [
    "NativeHealthLeaseSignature",
    "NativeKeyEvidence",
    "require_machine_context",
    "run_helper",
    "sign_health_key_registration",
    "sign_health_lease",
    "sign_protection_lease",
    "windows_current_user_sid",
]
