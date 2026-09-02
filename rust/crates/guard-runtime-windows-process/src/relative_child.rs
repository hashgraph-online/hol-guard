use std::ffi::OsStr;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::ptr::null_mut;

use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_READ, GENERIC_WRITE, SYNCHRONIZE, WRITE_DAC,
};
use windows_permissions::SecurityDescriptor;

use super::private_files::{mark_handle_for_delete, validate_handle};

const FILE_CREATE: u32 = 2;
const FILE_OPEN: u32 = 1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

const CHILD_ACCESS: DWORD = GENERIC_READ | GENERIC_WRITE | WRITE_DAC | DELETE | SYNCHRONIZE;
const CHILD_SHARE: DWORD = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const CHILD_OPTIONS: u32 =
    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut core::ffi::c_void,
    security_quality_of_service: *mut core::ffi::c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut u8,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

fn relative_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let encoded = name.encode_wide().collect::<Vec<_>>();
    if encoded.is_empty()
        || encoded.iter().any(|unit| {
            *unit == 0 || *unit == b'\\' as u16 || *unit == b'/' as u16 || *unit == b':' as u16
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private child name must be one normal path component",
        ));
    }
    Ok(encoded)
}

fn status_error(status: i32) -> io::Error {
    let code = status as u32;
    if code == STATUS_OBJECT_NAME_COLLISION {
        return io::Error::new(io::ErrorKind::AlreadyExists, "private child already exists");
    }
    if code == STATUS_OBJECT_NAME_NOT_FOUND || code == STATUS_OBJECT_PATH_NOT_FOUND {
        return io::Error::new(io::ErrorKind::NotFound, "private child is missing");
    }
    // SAFETY: ntdll maps this NTSTATUS to a Win32 error code.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn create_or_open_relative(
    parent: &std::fs::File,
    name: &OsStr,
    create: bool,
    security_descriptor: Option<&SecurityDescriptor>,
) -> io::Result<std::fs::File> {
    let mut name = relative_name(name)?;
    name.push(0);
    let byte_len = u16::try_from(name.len().saturating_sub(1).saturating_mul(2)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private child name is too long",
        )
    })?;
    let mut unicode = UnicodeString {
        length: byte_len,
        maximum_length: byte_len.saturating_add(2),
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle() as HANDLE,
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: security_descriptor
            .map(|descriptor| descriptor as *const _ as *mut _)
            .unwrap_or(null_mut()),
        security_quality_of_service: null_mut(),
    };
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;
    let options = if create {
        CHILD_OPTIONS | FILE_WRITE_THROUGH
    } else {
        CHILD_OPTIONS
    };
    // SAFETY: `parent` stays open for the call; `name` and `attributes` remain
    // valid; a successful handle is wrapped exactly once below.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            CHILD_ACCESS,
            &mut attributes,
            &mut io_status,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            CHILD_SHARE,
            if create { FILE_CREATE } else { FILE_OPEN },
            options,
            null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(status_error(status));
    }
    // SAFETY: NtCreateFile returned this handle exactly once.
    let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
    if let Err(error) = validate_handle(&file, false) {
        if create {
            let _ = mark_handle_for_delete(&file);
        }
        return Err(error);
    }
    Ok(file)
}

pub(super) fn create_relative_private_file(
    parent: &std::fs::File,
    name: &OsStr,
    security_descriptor: &SecurityDescriptor,
) -> io::Result<std::fs::File> {
    create_or_open_relative(parent, name, true, Some(security_descriptor))
}

pub(super) fn open_relative_private_file(
    parent: &std::fs::File,
    name: &OsStr,
) -> io::Result<std::fs::File> {
    create_or_open_relative(parent, name, false, None)
}
