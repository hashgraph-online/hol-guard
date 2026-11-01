"""Platform device-key helper operations, run and checked by the native runtime."""

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Literal, cast

from .contracts import KeyProtectionLevel, MachinePaths
from .device_key_windows_api import load_windows_token_api

DEVICE_KEY_HELPER_FEATURE = "native-device-key-helper-v1"
_MAX_HEALTH_LEASE_CLAIMS_BYTES = 4096
_STATUS_TIMEOUT_SECONDS = 10.0
# The runtime gives the helper 15 seconds.
_COMMAND_TIMEOUT_SECONDS = 30.0
_MAX_ANSWER_BYTES = 64 * 1024
_SYSTEM_SID = "S-1-5-18"
_PLATFORMS = {"Darwin": "macos", "Windows": "windows"}
_STATES = frozenset({"active", "absent", "unknown", "tampered"})
_PROTECTION_LEVELS = frozenset({"hardware-backed", "os-protected", "unknown"})
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


def _native_helper(
    paths: MachinePaths, verb: str, generation: str, *, system_name: str, payload: str | None = None
) -> dict[str, object]:
    """The runtime's checked answer from the platform helper for one operation."""

    from ..native_runtime import _run_native_process, native_runtime_status

    platform_name = _PLATFORMS.get(system_name)
    if platform_name is None:
        raise OSError("device_key_platform_unsupported")
    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or DEVICE_KEY_HELPER_FEATURE not in status.capabilities.features
    ):
        raise OSError("device_key_native_unavailable")
    request: dict[str, object] = {
        "schema": "device-key-helper.v1",
        "platform": platform_name,
        "runtime_root": str(paths.runtime_root),
        "verb": verb,
        "generation": generation,
    }
    if payload is not None:
        request["payload"] = payload
    output = _run_native_process(
        status.identity.path,
        ("device-key-helper", "--stdin"),
        input_text=json.dumps(request),
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_MAX_ANSWER_BYTES,
    )
    try:
        answer = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise OSError("device_key_native_unavailable")
    fields = cast(dict[str, object], answer)
    if fields.get("ok") is not True:
        raise OSError("device_key_probe_failed")
    return fields


def run_helper(paths: MachinePaths, verb: str, generation: str, *, system_name: str) -> NativeKeyEvidence:
    if verb not in {"create", "inspect", "delete"}:
        raise ValueError("device_key_request_invalid")
    if system_name not in _PLATFORMS:
        return NativeKeyEvidence("unknown", "unavailable", None, "device_key_platform_unsupported")
    answer = _native_helper(paths, verb, generation, system_name=system_name)
    state, level, reason = answer.get("state"), answer.get("protection_level"), answer.get("reason_code")
    public_key = answer.get("public_key_x963")
    if (
        state not in _STATES
        or level not in _PROTECTION_LEVELS
        or not isinstance(reason, str)
        or not (public_key is None or isinstance(public_key, str))
    ):
        raise OSError("device_key_probe_failed")
    return NativeKeyEvidence(
        cast(Literal["active", "absent", "unknown", "tampered"], state),
        cast(KeyProtectionLevel, level),
        base64.b64decode(public_key) if public_key is not None else None,
        reason,
    )


def _sign_payload_with_device_key(
    paths: MachinePaths,
    subcommand: str,
    generation: str,
    payload_text: str,
    *,
    system_name: str,
) -> NativeHealthLeaseSignature:
    answer = _native_helper(paths, subcommand, generation, system_name=system_name, payload=payload_text)
    signature = answer.get("signature")
    if not isinstance(signature, str):
        raise OSError("device_key_probe_failed")
    return NativeHealthLeaseSignature(base64.b64decode(signature))


def sign_health_lease(
    paths: MachinePaths, generation: str, canonical_claims: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    claims_text = _validated_canonical_health_lease_claims(canonical_claims)
    return _sign_payload_with_device_key(paths, "sign-health-lease", generation, claims_text, system_name=system_name)


def sign_protection_lease(
    paths: MachinePaths, generation: str, canonical_unsigned_lease: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    lease_text = _validated_canonical_protection_lease(canonical_unsigned_lease)
    return _sign_payload_with_device_key(
        paths, "sign-protection-lease", generation, lease_text, system_name=system_name
    )


def sign_health_key_registration(
    paths: MachinePaths, generation: str, canonical_registration: bytes, *, system_name: str
) -> NativeHealthLeaseSignature:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("device_key_request_invalid")
    registration_text = _validated_canonical_health_key_registration(canonical_registration)
    return _sign_payload_with_device_key(
        paths, "sign-health-key-registration", generation, registration_text, system_name=system_name
    )


def windows_current_user_sid() -> str:
    import ctypes
    from ctypes import wintypes

    windows_token_api = load_windows_token_api()

    token = wintypes.HANDLE()
    if not windows_token_api.open_process_token(windows_token_api.get_current_process(), 0x0008, ctypes.byref(token)):
        raise OSError("device_key_system_context_required")
    try:
        needed = wintypes.DWORD()
        if windows_token_api.get_token_information(token, 1, None, 0, ctypes.byref(needed)):
            raise OSError("device_key_system_context_required")
        if ctypes.get_last_error() != 122 or not 0 < needed.value <= 64 * 1024:
            raise OSError("device_key_system_context_required")
        buffer = ctypes.create_string_buffer(needed.value)
        if not windows_token_api.get_token_information(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError("device_key_system_context_required")
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID)).contents
        if not sid_pointer.value:
            raise OSError("device_key_system_context_required")
        sid_string = wintypes.LPWSTR()
        if not windows_token_api.convert_sid(sid_pointer, ctypes.byref(sid_string)):
            raise OSError("device_key_system_context_required")
        try:
            value = sid_string.value
            if not value:
                raise OSError("device_key_system_context_required")
            return str(value)
        finally:
            _ = windows_token_api.local_free(ctypes.cast(sid_string, wintypes.HLOCAL))
    finally:
        _ = windows_token_api.close_handle(token)


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
