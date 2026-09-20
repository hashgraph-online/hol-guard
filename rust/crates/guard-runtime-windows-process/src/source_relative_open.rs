use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path};
use std::ptr::null_mut;

use winapi::shared::ntdef::{
    HANDLE, LARGE_INTEGER, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    UNICODE_STRING,
};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::{
    FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_READ,
    FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
};

const FILE_OPEN: u32 = 1;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        handle: *mut HANDLE,
        desired_access: u32,
        attributes: *mut OBJECT_ATTRIBUTES,
        io_status: *mut IoStatusBlock,
        allocation_size: *mut LARGE_INTEGER,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
        ea_buffer: *mut std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

/// Open one child using the already checked parent object, not a DOS pathname.
pub(super) fn open_source_child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(super::invalid_path());
    }
    let mut wide = name.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide
            .iter()
            .any(|value| *value == 0 || *value == u16::from(b':'))
    {
        return Err(super::invalid_path());
    }
    let byte_length = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(super::invalid_path)?;
    let mut name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide.as_mut_ptr(),
    };
    let mut attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let access = if directory {
        FILE_LIST_DIRECTORY
            | FILE_READ_ATTRIBUTES
            | FILE_READ_EA
            | FILE_TRAVERSE
            | READ_CONTROL
            | SYNCHRONIZE
    } else {
        FILE_GENERIC_READ
    };
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let mut raw = null_mut();
    let mut status_block = IoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: The parent remains borrowed and open. Both pointer-bearing
    // structs and the counted UTF-16 buffer live through this synchronous
    // call. FILE_OPEN cannot create an object or apply a security descriptor.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &mut attributes,
            &mut status_block,
            null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            options,
            null_mut(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: This function maps the returned NTSTATUS without pointers.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(super::invalid_path());
    }
    // SAFETY: A successful synchronous NtCreateFile returned one new owned
    // handle. No raw handle escapes, and failed validation drops it once.
    let file = unsafe { File::from_raw_handle(raw as RawHandle) };
    super::validate_handle(&file, directory)?;
    Ok(file)
}
