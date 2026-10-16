//! Handle-based file identity queries: link counts and same-object checks.

use std::io;
use std::mem::zeroed;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
use winapi::um::winnt::{
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::private_files::{
    mark_handle_for_delete, open_raw, open_raw_with_access, validate_handle,
};

/// Return whether an existing regular file has exactly one directory entry.
/// The link count is read from the opened handle so aliases cannot be hidden
/// by a path-only metadata lookup.
pub fn is_single_link_file(path: &Path) -> io::Result<bool> {
    let file = open_raw_with_access(
        path,
        false,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_READ_ATTRIBUTES,
    )?;
    validate_handle(&file, false)?;
    is_single_link_handle(&file)
}

/// Return whether an already-open file has exactly one directory entry.
pub fn is_single_link_handle(file: &std::fs::File) -> io::Result<bool> {
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: The output buffer is correctly sized and the handle remains
    // open for the synchronous query.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) }
        == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information.nNumberOfLinks == 1)
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
