//! Narrow Windows process creation support for the managed native runtime.
//!
//! The runtime is intentionally `unsafe_code = "forbid"`. Windows' stable
//! standard-library process API does not expose `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`,
//! so the small amount of Win32 FFI needed for the inheritance barrier lives in
//! this companion crate. The public API owns every process, pipe, and attribute
//! handle and never exposes a raw handle to callers.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_op_in_unsafe_fn))]

use std::ffi::OsStr;
use std::io;
use std::path::Path;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::ManagedChild;

#[cfg(windows)]
pub use windows::{
    bind_directory, bind_private_directory, create_private_directory, create_private_file,
    delete_private_file_handle, open_private_directory, open_private_file, process_start_marker,
    remove_file_if_same, terminate_process, terminate_process_verified, wait_for_process_exit,
    PrivateDirectoryBinding,
};

#[cfg(windows)]
pub fn spawn_managed_child(executable: &Path, args: &[&OsStr]) -> io::Result<ManagedChild> {
    windows::spawn_managed_child(executable, args)
}

#[cfg(not(windows))]
pub struct ManagedChild;

#[cfg(not(windows))]
pub fn spawn_managed_child(_executable: &Path, _args: &[&OsStr]) -> io::Result<ManagedChild> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows managed process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn wait_for_process_exit(_process_id: u32, _timeout: std::time::Duration) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn process_start_marker(_process_id: u32) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn terminate_process(_process_id: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn terminate_process_verified(
    _process_id: u32,
    _expected_start_marker: Option<&str>,
    _timeout: std::time::Duration,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}
