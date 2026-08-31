"""Windows owner and DACL verification for native policy state."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from .native_policy_snapshot_constants import (
    _WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
    _WINDOWS_DACL_SECURITY_INFORMATION,
    _WINDOWS_FILE_ALL_ACCESS,
    _WINDOWS_INHERITED_ACE,
    _WINDOWS_OWNER_SECURITY_INFORMATION,
    _WINDOWS_SE_DACL_PROTECTED,
    _WINDOWS_SE_FILE_OBJECT,
    _WINDOWS_SYSTEM_SID,
    NativePolicySnapshotError,
)


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _read_security_descriptor(
    handle: Any,
    advapi32: Any,
    ctypes_module: Any,
    wintypes: Any,
) -> tuple[Any, Any, Any]:
    descriptor = ctypes_module.c_void_p()
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes_module.POINTER(ctypes_module.c_void_p),
        ctypes_module.POINTER(ctypes_module.c_void_p),
        ctypes_module.POINTER(ctypes_module.c_void_p),
        ctypes_module.POINTER(ctypes_module.c_void_p),
        ctypes_module.POINTER(ctypes_module.c_void_p),
    ]
    get_security_info.restype = wintypes.DWORD
    owner = ctypes_module.c_void_p()
    group = ctypes_module.c_void_p()
    dacl = ctypes_module.c_void_p()
    sacl = ctypes_module.c_void_p()
    if (
        int(
            get_security_info(
                handle,
                _WINDOWS_SE_FILE_OBJECT,
                _WINDOWS_OWNER_SECURITY_INFORMATION | _WINDOWS_DACL_SECURITY_INFORMATION,
                ctypes_module.byref(owner),
                ctypes_module.byref(group),
                ctypes_module.byref(dacl),
                ctypes_module.byref(sacl),
                ctypes_module.byref(descriptor),
            )
        )
        != 0
        or not descriptor
        or not owner
        or not dacl
    ):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    return descriptor, owner, dacl


def _sid_converter(advapi32: Any, ctypes_module: Any, wintypes: Any) -> Any:
    convert_sid = advapi32.ConvertSidToStringSidW
    convert_sid.argtypes = [ctypes_module.c_void_p, ctypes_module.POINTER(wintypes.LPWSTR)]
    convert_sid.restype = wintypes.BOOL
    return convert_sid


def _sid_string(
    value: Any,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
) -> str:
    sid_string = wintypes.LPWSTR()
    if not convert_sid(value, ctypes_module.byref(sid_string)):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    try:
        return str(sid_string.value)
    finally:
        local_free(sid_string)


def _verify_owner(
    owner: Any,
    owner_sid: str,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
) -> None:
    if _sid_string(owner, convert_sid, local_free, ctypes_module, wintypes) != owner_sid:
        raise NativePolicySnapshotError("native_policy_windows_acl_not_private")


def _verify_protected_control(descriptor: Any, advapi32: Any, ctypes_module: Any, wintypes: Any) -> None:
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    get_control = advapi32.GetSecurityDescriptorControl
    get_control.argtypes = [
        ctypes_module.c_void_p,
        ctypes_module.POINTER(wintypes.WORD),
        ctypes_module.POINTER(wintypes.DWORD),
    ]
    get_control.restype = wintypes.BOOL
    if not get_control(descriptor, ctypes_module.byref(control), ctypes_module.byref(revision)) or not (
        control.value & _WINDOWS_SE_DACL_PROTECTED
    ):
        raise NativePolicySnapshotError("native_policy_windows_acl_not_private")


def _verify_acl_entries(
    dacl: Any,
    owner_sid: str,
    directory: bool,
    advapi32: Any,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
) -> None:
    class AclSizeInformation(ctypes_module.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    acl_info = AclSizeInformation()
    get_acl_information = advapi32.GetAclInformation
    get_acl_information.argtypes = [ctypes_module.c_void_p, ctypes_module.c_void_p, wintypes.DWORD, wintypes.DWORD]
    get_acl_information.restype = wintypes.BOOL
    if not get_acl_information(dacl, ctypes_module.byref(acl_info), ctypes_module.sizeof(acl_info), 2):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    expected_sids = {owner_sid, _WINDOWS_SYSTEM_SID}
    seen_sids: set[str] = set()
    for index in range(int(acl_info.AceCount)):
        sid = _verify_acl_entry(
            dacl,
            index,
            directory,
            expected_sids,
            advapi32,
            convert_sid,
            local_free,
            ctypes_module,
            wintypes,
        )
        if sid in seen_sids:
            raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
        seen_sids.add(sid)
    required_sids = {_WINDOWS_SYSTEM_SID} if owner_sid == _WINDOWS_SYSTEM_SID else expected_sids
    if seen_sids != required_sids:
        raise NativePolicySnapshotError("native_policy_windows_acl_not_private")


def _verify_acl_entry(
    dacl: Any,
    index: int,
    directory: bool,
    expected_sids: set[str],
    advapi32: Any,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
) -> str:
    ace = ctypes_module.c_void_p()
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes_module.c_void_p,
        wintypes.DWORD,
        ctypes_module.POINTER(ctypes_module.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    if not get_ace(dacl, index, ctypes_module.byref(ace)) or not ace:
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    address = ace.value
    if not isinstance(address, int):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    ace_type = ctypes_module.c_ubyte.from_address(address).value
    ace_flags = ctypes_module.c_ubyte.from_address(address + 1).value
    ace_size = ctypes_module.c_ushort.from_address(address + 2).value
    mask = ctypes_module.c_uint32.from_address(address + 4).value
    expected_flags = 0x03 if directory else 0
    if (
        ace_type != _WINDOWS_ACCESS_ALLOWED_ACE_TYPE
        or ace_flags != expected_flags
        or ace_flags & _WINDOWS_INHERITED_ACE
        or ace_size < 12
        or mask != _WINDOWS_FILE_ALL_ACCESS
    ):
        raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
    sid = _sid_string(
        ctypes_module.c_void_p(address + 8),
        convert_sid,
        local_free,
        ctypes_module,
        wintypes,
    )
    if sid not in expected_sids:
        raise NativePolicySnapshotError("native_policy_windows_acl_not_private")
    return sid


def _windows_verify_private_dacl(handle: Any, *, owner_sid: str, directory: bool) -> None:
    """Require a protected DACL containing only owner and SYSTEM full access."""

    from ctypes import wintypes

    api = _snapshot_api()
    advapi32 = api._windows_dll("advapi32")
    descriptor, owner, dacl = _read_security_descriptor(handle, advapi32, ctypes, wintypes)
    kernel32 = api._windows_dll("kernel32")
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    try:
        convert_sid = _sid_converter(advapi32, ctypes, wintypes)
        _verify_owner(owner, owner_sid, convert_sid, local_free, ctypes, wintypes)
        _verify_protected_control(descriptor, advapi32, ctypes, wintypes)
        _verify_acl_entries(
            dacl,
            owner_sid,
            directory,
            advapi32,
            convert_sid,
            local_free,
            ctypes,
            wintypes,
        )
    finally:
        local_free(descriptor)
