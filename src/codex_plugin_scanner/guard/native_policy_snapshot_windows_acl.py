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

_WINDOWS_ADMINISTRATORS_SID = "S-1-5-32-544"
_WINDOWS_OWNER_RIGHTS_SID = "S-1-3-4"
_WINDOWS_ALL_APP_PACKAGES_SID = "S-1-15-2-1"


def _windows_sid_class(sid: str | None, owner_sid: str | None) -> str:
    """Classify an ACL principal without emitting a user-specific SID."""

    if sid is None:
        return "unknown"
    if owner_sid is not None and sid == owner_sid:
        return "expected-owner"
    if sid == _WINDOWS_SYSTEM_SID:
        return "system"
    if sid == _WINDOWS_ADMINISTRATORS_SID:
        return "administrators"
    if sid == _WINDOWS_OWNER_RIGHTS_SID:
        return "owner-rights"
    if sid == _WINDOWS_ALL_APP_PACKAGES_SID:
        return "all-app-packages"
    return "other"


def _windows_owner_is_trusted(actual_sid: str, owner_sid: str) -> bool:
    """Accept only owners that already control the local Windows host."""

    return actual_sid in {owner_sid, _WINDOWS_SYSTEM_SID, _WINDOWS_ADMINISTRATORS_SID}


def _windows_acl_not_private(
    *,
    protected: bool | None = None,
    ace_count: int | None = None,
    ace_type: int | None = None,
    ace_flags: int | None = None,
    mask: int | None = None,
    sid_class: str | None = None,
) -> NativePolicySnapshotError:
    """Build bounded ACL diagnostics without disclosing local identity."""

    details = [
        f"protected={int(protected)}" if protected is not None else "protected=unknown",
        f"ace_count={ace_count}" if ace_count is not None else "ace_count=unknown",
    ]
    if ace_type is not None:
        details.append(f"ace_type={'access_allowed' if ace_type == _WINDOWS_ACCESS_ALLOWED_ACE_TYPE else 'other'}")
    if ace_flags is not None:
        details.append(f"ace_flags=0x{ace_flags:02x}")
    if mask is not None:
        details.append(f"mask={'full' if mask == _WINDOWS_FILE_ALL_ACCESS else 'other'}")
    if sid_class is not None:
        details.append(f"sid={sid_class}")
    return NativePolicySnapshotError("native_policy_windows_acl_not_private:" + ",".join(details))


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
    actual_sid = _sid_string(owner, convert_sid, local_free, ctypes_module, wintypes)
    if not _windows_owner_is_trusted(actual_sid, owner_sid):
        raise _windows_acl_not_private(sid_class=_windows_sid_class(actual_sid, owner_sid))


def _verify_protected_control(descriptor: Any, advapi32: Any, ctypes_module: Any, wintypes: Any) -> bool:
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    get_control = advapi32.GetSecurityDescriptorControl
    get_control.argtypes = [
        ctypes_module.c_void_p,
        ctypes_module.POINTER(wintypes.WORD),
        ctypes_module.POINTER(wintypes.DWORD),
    ]
    get_control.restype = wintypes.BOOL
    if not get_control(descriptor, ctypes_module.byref(control), ctypes_module.byref(revision)):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    protected = bool(control.value & _WINDOWS_SE_DACL_PROTECTED)
    if not protected:
        raise _windows_acl_not_private(protected=protected)
    return protected


def _verify_acl_entries(
    dacl: Any,
    owner_sid: str,
    directory: bool,
    advapi32: Any,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
    protected: bool,
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
            owner_sid,
            advapi32,
            convert_sid,
            local_free,
            ctypes_module,
            wintypes,
            protected,
            int(acl_info.AceCount),
        )
        if sid in seen_sids:
            raise _windows_acl_not_private(
                protected=protected,
                ace_count=int(acl_info.AceCount),
                sid_class=_windows_sid_class(sid, owner_sid),
            )
        seen_sids.add(sid)
    required_sids = {_WINDOWS_SYSTEM_SID} if owner_sid == _WINDOWS_SYSTEM_SID else expected_sids
    if seen_sids != required_sids:
        raise _windows_acl_not_private(
            protected=protected,
            ace_count=int(acl_info.AceCount),
            sid_class="other",
        )


def _verify_acl_entry(
    dacl: Any,
    index: int,
    directory: bool,
    expected_sids: set[str],
    owner_sid: str,
    advapi32: Any,
    convert_sid: Any,
    local_free: Any,
    ctypes_module: Any,
    wintypes: Any,
    protected: bool,
    ace_count: int,
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
        raise _windows_acl_not_private(
            protected=protected,
            ace_count=ace_count,
            ace_type=ace_type,
            ace_flags=ace_flags,
            mask=mask,
        )
    sid = _sid_string(
        ctypes_module.c_void_p(address + 8),
        convert_sid,
        local_free,
        ctypes_module,
        wintypes,
    )
    if sid not in expected_sids:
        raise _windows_acl_not_private(
            protected=protected,
            ace_count=ace_count,
            ace_type=ace_type,
            ace_flags=ace_flags,
            mask=mask,
            sid_class=_windows_sid_class(sid, owner_sid),
        )
    return sid


def _windows_verify_private_owner(handle: Any, *, owner_sid: str) -> None:
    """Reject a foreign owner before changing an existing object's DACL."""

    from ctypes import wintypes

    api = _snapshot_api()
    advapi32 = api._windows_dll("advapi32")
    descriptor = ctypes.c_void_p()
    owner = ctypes.c_void_p()
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security_info.restype = wintypes.DWORD
    if (
        int(
            get_security_info(
                handle,
                _WINDOWS_SE_FILE_OBJECT,
                _WINDOWS_OWNER_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                None,
                None,
                ctypes.byref(descriptor),
            )
        )
        != 0
        or not descriptor
        or not owner
    ):
        raise NativePolicySnapshotError("native_policy_windows_acl_verify_failed")
    kernel32 = api._windows_dll("kernel32")
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    try:
        convert_sid = _sid_converter(advapi32, ctypes, wintypes)
        _verify_owner(owner, owner_sid, convert_sid, local_free, ctypes, wintypes)
    finally:
        local_free(descriptor)


def _windows_verify_private_dacl(handle: Any, *, owner_sid: str, directory: bool) -> None:
    """Require a protected DACL containing only the current principal and SYSTEM."""

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
        protected = _verify_protected_control(descriptor, advapi32, ctypes, wintypes)
        _verify_acl_entries(
            dacl,
            owner_sid,
            directory,
            advapi32,
            convert_sid,
            local_free,
            ctypes,
            wintypes,
            protected,
        )
    finally:
        local_free(descriptor)
