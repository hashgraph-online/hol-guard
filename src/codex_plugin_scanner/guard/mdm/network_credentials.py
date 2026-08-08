"""Native operating-system credential retrieval for managed proxy authentication."""

from __future__ import annotations

import ctypes
import platform
import subprocess
from ctypes import wintypes
from pathlib import Path

_PROXY_CREDENTIAL_SERVICE = "hol-guard-enterprise-proxy-v1"


def _read_macos(account: str) -> str | None:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                _PROXY_CREDENTIAL_SERVICE,
                "-a",
                account,
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.rstrip("\r\n")
    return value or None


def _read_linux(account: str) -> str | None:
    executable = Path("/usr/bin/secret-tool")
    if not executable.is_file():
        return None
    try:
        completed = subprocess.run(
            [
                str(executable),
                "lookup",
                "service",
                _PROXY_CREDENTIAL_SERVICE,
                "account",
                account,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.rstrip("\r\n")
    return value or None


def _read_windows(account: str) -> str | None:
    if not hasattr(ctypes, "windll"):
        return None

    class _CredentialAttribute(ctypes.Structure):
        _fields_ = [
            ("Keyword", wintypes.LPWSTR),
            ("Flags", wintypes.DWORD),
            ("ValueSize", wintypes.DWORD),
            ("Value", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class _Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.POINTER(_CredentialAttribute)),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    credential_pointer = ctypes.POINTER(_Credential)()
    advapi32 = ctypes.windll.advapi32
    cred_read = advapi32.CredReadW
    cred_read.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(_Credential))]
    cred_read.restype = wintypes.BOOL
    cred_free = advapi32.CredFree
    cred_free.argtypes = [ctypes.c_void_p]
    cred_free.restype = None
    target = f"{_PROXY_CREDENTIAL_SERVICE}:{account}"
    if not cred_read(target, 1, 0, ctypes.byref(credential_pointer)):
        return None
    try:
        credential = credential_pointer.contents
        size = int(credential.CredentialBlobSize)
        if size <= 0 or not credential.CredentialBlob:
            return None
        raw = ctypes.string_at(credential.CredentialBlob, size)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.decode("utf-16-le")
        return value or None
    except (UnicodeDecodeError, ValueError):
        return None
    finally:
        cred_free(credential_pointer)


def read_proxy_credential_record(account: str) -> str | None:
    """Read one bounded proxy-auth record from the native OS credential store."""

    system_name = platform.system()
    if system_name == "Darwin":
        return _read_macos(account)
    if system_name == "Windows":
        return _read_windows(account)
    if system_name == "Linux":
        return _read_linux(account)
    return None


__all__ = ["read_proxy_credential_record"]
