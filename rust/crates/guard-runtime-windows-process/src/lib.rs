//! Narrow Windows process creation support for the managed native runtime.
//!
//! The runtime is intentionally `unsafe_code = "forbid"`. Windows' stable
//! standard-library process API does not expose `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`,
//! so the small amount of Win32 FFI needed for the inheritance barrier lives in
//! this companion crate. Public APIs own every process, pipe and attribute
//! handle. Suspended-process attachment accepts owned handles, never borrows.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_op_in_unsafe_fn))]

use std::ffi::OsStr;
use std::io;
use std::path::Path;

#[cfg(windows)]
mod drives;
#[cfg(windows)]
mod host_name;
#[cfg(windows)]
mod known_folders;
#[cfg(windows)]
mod owner;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod secure_storage;
#[cfg(windows)]
mod trusted_directories;
#[cfg(all(test, windows))]
#[path = "../../../test_support/unique_nanos.rs"]
mod unique_nanos;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::ManagedChild;
#[cfg(windows)]
pub use windows::{
    attach_suspended_process, capture_managed_child, capture_owned_child, capture_pipes,
    disinherit_standard_handles, CaptureCommand, CapturePipes, CapturedOutput, ChildJobGuard,
    ChildTree, InheritWindow, ResourceLimits, CHILD_TREE_CREATION_FLAGS,
};

#[cfg(windows)]
pub use windows::{
    bind_directory, bind_private_directory, bind_readonly_directory, create_private_directory,
    create_private_file, delete_private_file_handle, directory_file_id, handle_file_id,
    is_single_link_file, is_single_link_handle, open_bound_executable_file,
    open_bound_regular_file, open_bound_replaceable_file, open_private_directory,
    open_private_file, open_skill_directory, path_is_within, path_stat, process_liveness,
    process_parent_ids, process_start_marker, regular_file_id, remove_file_if_same,
    running_process_image_path, running_process_start_marker, terminate_process,
    terminate_process_verified, wait_for_process_exit, FileId, PathStat, PrivateDirectoryBinding,
};

#[cfg(windows)]
pub use drives::local_drive_letters;

#[cfg(windows)]
pub use host_name::dns_host_name;

#[cfg(windows)]
pub use known_folders::{
    roaming_appdata_directory, trusted_install_roots, user_profile_directory, windows_directory,
};

#[cfg(windows)]
pub use trusted_directories::{
    kernel_system_directory, kernel_windows_directory, real_directory, real_regular_file,
};

#[cfg(windows)]
pub use owner::owned_by_current_user;

#[cfg(windows)]
pub use windows::{
    command_line_to_argv, process_creation_time, process_owner_sid, terminate_if_creation_time,
};

#[cfg(windows)]
pub use registry::{read_machine_registry_string, MachineRegistryString};

#[cfg(windows)]
pub use secure_storage::{
    credential_delete, credential_read, credential_write, dpapi_protect, dpapi_unprotect,
    secure_zero,
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

/// Only Windows has drive letters.
#[cfg(not(windows))]
pub fn local_drive_letters() -> Option<Vec<char>> {
    None
}

/// Only Windows has owner SIDs.
#[cfg(not(windows))]
pub fn owned_by_current_user(_path: &Path) -> bool {
    false
}

#[cfg(not(windows))]
pub fn process_creation_time(_process_id: u32) -> Option<u64> {
    None
}

#[cfg(not(windows))]
pub fn process_owner_sid(_process_id: u32) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn terminate_if_creation_time(
    _process_id: u32,
    _expected_creation_time: u64,
    _timeout: Option<std::time::Duration>,
) -> bool {
    false
}

/// Only Windows has known folders.
#[cfg(not(windows))]
pub fn user_profile_directory() -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(windows))]
pub fn roaming_appdata_directory() -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(windows))]
pub fn kernel_windows_directory() -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn kernel_system_directory() -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn real_directory(_path: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn real_regular_file(_path: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn command_line_to_argv(_command: &str) -> Option<Vec<String>> {
    None
}

#[cfg(not(windows))]
pub fn process_liveness(_process_id: u32) -> Option<bool> {
    None
}

#[cfg(not(windows))]
pub fn process_start_marker(_process_id: u32) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn running_process_image_path(_process_id: u32) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process support is unavailable",
    ))
}

#[cfg(not(windows))]
pub fn running_process_start_marker(_process_id: u32) -> io::Result<String> {
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
