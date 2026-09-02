use std::ffi::OsStr;
use std::io;
use std::mem::{offset_of, size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::Path;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{
    CreateFileW, GetFileInformationByHandle, GetFileType, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO, FILE_RENAME_INFO,
    OPEN_EXISTING,
};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::minwinbase::{FileAttributeTagInfo, FileDispositionInfo, SECURITY_ATTRIBUTES};
use winapi::um::winbase::{
    GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS, FILE_TYPE_DISK,
};
use winapi::um::winnt::{
    DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, GENERIC_READ, GENERIC_WRITE, WRITE_DAC,
};
use windows_permissions::constants::{
    AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation,
};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::GetSecurityInfo;
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};

const CREATE_NEW: DWORD = 1;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_FILE_EXISTS: i32 = 80;
const FILE_FLAG_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;
const FILE_FLAG_WRITE_THROUGH: DWORD = 0x8000_0000;
const FILE_RENAME_INFORMATION_CLASS: u32 = 10;

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSetInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut u8,
        length: u32,
        file_information_class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

/// Create one owner-private file with its security descriptor applied by the
/// kernel as part of the create operation. The descriptor must remain valid
/// for the duration of this call; callers normally pass a borrowed
/// `windows_permissions::SecurityDescriptor` backed by a `LocalBox`.
pub fn create_private_file(
    path: &Path,
    security_descriptor: &SecurityDescriptor,
) -> io::Result<std::fs::File> {
    let path_w = super::wide_path(path)?;
    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: security_descriptor as *const _ as *mut _,
        bInheritHandle: FALSE,
    };
    // SAFETY: The path is NUL-terminated; SECURITY_ATTRIBUTES and its
    // descriptor remain valid through the synchronous CreateFileW call.
    let raw = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | WRITE_DAC | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &mut security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS
        ) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, error));
        }
        return Err(error);
    }
    // SAFETY: CreateFileW returned this handle exactly once.
    let file = unsafe { std::fs::File::from_raw_handle(raw as RawHandle) };
    if let Err(error) = validate_handle(&file, false) {
        // The object was created by this call. Keep cleanup bound to the
        // opened handle so a pathname replacement cannot delete another file.
        let _ = mark_handle_for_delete(&file);
        return Err(error);
    }
    Ok(file)
}

/// Open an existing regular file with enough access to repair its DACL.
pub fn open_private_file(path: &Path) -> io::Result<std::fs::File> {
    open_existing(path, false)
}

/// Open an existing directory with enough access to repair its DACL.
pub fn open_private_directory(path: &Path) -> io::Result<std::fs::File> {
    open_existing(path, true)
}

pub(super) fn open_existing(path: &Path, directory: bool) -> io::Result<std::fs::File> {
    let file = open_raw(
        path,
        directory,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        true,
    )?;
    validate_handle(&file, directory)?;
    Ok(file)
}

pub(super) fn open_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
    allow_add_file: bool,
) -> io::Result<std::fs::File> {
    let file = open_raw_directory_bound(path, allow_acl_repair, allow_add_file, false)?;
    validate_handle(&file, true)?;
    Ok(file)
}

/// Open a directory while keeping checked ancestry from being renamed away.
/// Barrier handles never share delete and never take GENERIC_WRITE, so the
/// bound directory cannot be renamed and children can still be created.
pub(super) fn open_raw_directory_bound(
    path: &Path,
    allow_acl_repair: bool,
    allow_add_file: bool,
    allow_delete: bool,
) -> io::Result<std::fs::File> {
    let mut access = GENERIC_READ | FILE_TRAVERSE;
    if allow_acl_repair {
        access |= WRITE_DAC;
    }
    if allow_add_file {
        access |= FILE_ADD_FILE;
    }
    if allow_delete {
        access |= DELETE;
    }
    open_raw_with_access(path, true, FILE_SHARE_READ | FILE_SHARE_WRITE, access)
}

/// Open the rename parent used as FILE_RENAME_INFORMATION.RootDirectory.
pub(super) fn open_rename_directory(path: &Path) -> io::Result<std::fs::File> {
    let file = open_raw_with_access(
        path,
        true,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
    )?;
    validate_handle(&file, true)?;
    Ok(file)
}

pub(super) fn open_raw(
    path: &Path,
    directory: bool,
    share_mode: DWORD,
    delete_access: bool,
) -> io::Result<std::fs::File> {
    let desired_access =
        GENERIC_READ | GENERIC_WRITE | WRITE_DAC | if delete_access { DELETE } else { 0 };
    open_raw_with_access(path, directory, share_mode, desired_access)
}

fn open_raw_with_access(
    path: &Path,
    directory: bool,
    share_mode: DWORD,
    desired_access: DWORD,
) -> io::Result<std::fs::File> {
    let path_w = super::wide_path(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    // SAFETY: The path is NUL-terminated and all pointers remain valid for
    // the synchronous CreateFileW call.
    let raw = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            desired_access,
            share_mode,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | flags,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned this handle exactly once.
    Ok(unsafe { std::fs::File::from_raw_handle(raw as RawHandle) })
}

pub(super) fn validate_handle(handle: &std::fs::File, directory: bool) -> io::Result<()> {
    let raw = handle.as_raw_handle() as HANDLE;
    // SAFETY: `raw` is a live handle borrowed for the duration of each query.
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(invalid_object(directory));
    }
    // `winapi` 0.3.9 exposes the first FILE_ATTRIBUTE_TAG_INFO field under
    // the historical `NextEntryOffset` name, but the layout is the documented
    // FileAttributes DWORD followed by ReparseTag.
    let mut tag_info = unsafe { zeroed::<FILE_ATTRIBUTE_TAG_INFO>() };
    // SAFETY: `tag_info` is a correctly-sized output buffer for the requested
    // information class, and `raw` remains open through the call.
    if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileAttributeTagInfo,
            &mut tag_info as *mut FILE_ATTRIBUTE_TAG_INFO as *mut _,
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as DWORD,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: `information` is a correctly-sized output buffer and `raw` is
    // borrowed only for this synchronous query.
    if unsafe { GetFileInformationByHandle(raw, &mut information) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    let attributes = information.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag_info.NextEntryOffset & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag_info.ReparseTag != 0
        || (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(invalid_object(directory));
    }
    Ok(())
}

fn invalid_object(directory: bool) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        if directory {
            "opened object is not a non-reparse directory"
        } else {
            "opened object is not a non-reparse regular file"
        },
    )
}

fn trusted_private_owner(applied: &Sid, current: &Sid) -> bool {
    if applied == current {
        return true;
    }
    let Ok(system) = "S-1-5-18".parse::<LocalBox<Sid>>() else {
        return false;
    };
    if applied == system.as_ref() {
        return true;
    }
    let Ok(administrators) = "S-1-5-32-544".parse::<LocalBox<Sid>>() else {
        return false;
    };
    applied == administrators.as_ref()
}

/// Verify the exact owner-private file policy before a handle participates in
/// an atomic replacement. This check is intentionally inside the companion
/// API; callers cannot accidentally replace a destination without validating
/// both the source and the existing destination.
pub(super) fn verify_private_file(handle: &std::fs::File) -> io::Result<()> {
    let owner = current_process_sid()
        .map_err(|_| io::Error::other("current Windows owner SID unavailable"))?;
    let applied = GetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner | SecurityInformation::ProtectedDacl,
    )
    .map_err(|_| io::Error::other("private file security descriptor unavailable"))?;
    let Some(applied_owner) = applied.owner() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file owner is missing",
        ));
    };
    if !trusted_private_owner(applied_owner, owner.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file owner does not match the current SID",
        ));
    }
    let sddl = applied
        .as_sddl()
        .map_err(|_| io::Error::other("private file security descriptor unavailable"))?;
    if !sddl.to_string_lossy().contains("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file DACL is inheritable",
        ));
    }
    let system = "S-1-5-18"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| io::Error::other("SYSTEM SID unavailable"))?;
    let dacl = applied
        .dacl()
        .ok_or_else(|| io::Error::other("private file DACL unavailable"))?;
    let mut owner_allowed = false;
    let mut system_allowed = false;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| io::Error::other("private file DACL unavailable"))?;
        if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
            || !ace.mask().contains(AccessRights::FileAllAccess)
            || ace.flags().contains(AceFlags::Inherited)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file DACL is not owner-private",
            ));
        }
        let sid = ace
            .sid()
            .ok_or_else(|| io::Error::other("private file DACL unavailable"))?;
        if sid == owner.as_ref() {
            owner_allowed = true;
        } else if sid == system.as_ref() {
            system_allowed = true;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file DACL contains an unexpected trustee",
            ));
        }
    }
    if !owner_allowed || (!system_allowed && owner.as_ref() != system.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file DACL lacks the required owner and SYSTEM entries",
        ));
    }
    Ok(())
}

/// Delete a newly-created private file through its already-open handle.
pub fn delete_private_file_handle(handle: &std::fs::File) -> io::Result<()> {
    validate_handle(handle, false)?;
    // Deletion is a security-sensitive operation. A valid regular-file
    // handle is not sufficient: callers must not be able to remove a
    // same-name object owned by another principal or carrying an inherited
    // DACL. Keep the ownership and ACL check on the already-open handle so
    // pathname replacement cannot redirect this operation.
    verify_private_file(handle)?;
    mark_handle_for_delete(handle)
}

pub(super) fn mark_handle_for_delete(handle: &std::fs::File) -> io::Result<()> {
    let mut disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: The handle was opened with DELETE access; the disposition buffer
    // remains valid for this synchronous call.
    if unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            &mut disposition as *mut FILE_DISPOSITION_INFO as *mut _,
            size_of::<FILE_DISPOSITION_INFO>() as DWORD,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn rename_into_directory(
    parent: &std::fs::File,
    source: &std::fs::File,
    destination: &OsStr,
) -> io::Result<()> {
    let name = destination.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private destination name is invalid",
        ));
    }
    // FILE_RENAME_INFO is padded after FileName[1]; copying at
    // size_of - sizeof(WCHAR) overwrites the name by two bytes.
    let header_size = offset_of!(FILE_RENAME_INFO, FileName);
    let byte_count = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private name is too long"))?;
    let buffer_size = header_size
        .checked_add(byte_count)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private name is too long"))?;
    let mut buffer = vec![0u8; buffer_size];
    // SAFETY: The buffer is sized to include the fixed header and the exact
    // UTF-16 payload expected by FILE_RENAME_INFO.
    unsafe {
        let info = buffer.as_mut_ptr() as *mut FILE_RENAME_INFO;
        (*info).ReplaceIfExists = TRUE;
        (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = byte_count as DWORD;
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const u8,
            buffer.as_mut_ptr().add(header_size),
            byte_count,
        );
    }
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: `source` is a live DELETE-capable handle and `buffer` remains
    // valid for the synchronous FileRenameInformation call.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut io_status,
            buffer.as_mut_ptr(),
            buffer_size as u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        // SAFETY: ntdll maps this NTSTATUS to a Win32 error code.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Ok(())
}

/// Delete the path's currently opened object only when it is the same object
/// as `expected`. Comparison and deletion both use owned handles, preventing a
/// same-user pathname replacement from redirecting cleanup to a new file.
pub fn remove_file_if_same(path: &Path, expected: &std::fs::File) -> io::Result<bool> {
    let current = match open_raw(
        path,
        false,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        true,
    ) {
        Ok(current) => current,
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
    };
    validate_handle(&current, false)?;
    if file_information(expected.as_raw_handle() as HANDLE)?
        != file_information(current.as_raw_handle() as HANDLE)?
    {
        return Ok(false);
    }
    mark_handle_for_delete(&current)?;
    Ok(true)
}

pub(super) fn file_information(handle: HANDLE) -> io::Result<(DWORD, DWORD, DWORD)> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is a plain output struct; handle
    // stays owned during this query.
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok((
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}
