"""Bounded execution contract for platform-native device-key helpers."""

from __future__ import annotations

import base64
import ctypes
import json
import ntpath
import os
import subprocess
from dataclasses import dataclass
from typing import Literal, cast

from .contracts import KeyProtectionLevel, MachinePaths

_MAX_HELPER_OUTPUT_BYTES = 16 * 1024
_HELPER_TIMEOUT_SECONDS = 15
_SYSTEM_SID = "S-1-5-18"


@dataclass(frozen=True, slots=True)
class NativeKeyEvidence:
    state: Literal["active", "absent", "unknown", "tampered"]
    protection_level: KeyProtectionLevel
    public_key_x963: bytes | None
    reason_code: str


def windows_directory() -> str:
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("device_key_probe_failed")
    return ntpath.normpath(str(buffer.value))


def run_helper(paths: MachinePaths, verb: str, generation: str, *, system_name: str) -> NativeKeyEvidence:
    if verb not in {"create", "inspect", "delete"}:
        raise ValueError("device_key_request_invalid")
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
        return NativeKeyEvidence("unknown", "unavailable", None, "device_key_platform_unsupported")
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
    if len(result.stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT_BYTES or len(result.stderr.encode("utf-8")) > 4096:
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


__all__ = ["NativeKeyEvidence", "require_machine_context", "run_helper", "windows_current_user_sid"]
