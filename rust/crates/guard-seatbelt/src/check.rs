//! Asking the kernel what the sandbox around this process allows.
//!
//! `sandbox_check` answers from the process's seatbelt profile alone: it
//! never performs the operation. It returns 1 when the profile denies it,
//! 0 when the profile allows it or the process has no sandbox, and -1 on
//! error, so only 1 counts as a denial here.
//!
//! A path check answers 1 for a path that does not exist, sandbox or not,
//! so only an existing directory is asked about. Seatbelt write rules name
//! subpaths, so a directory's own answer is its contents' answer too.
//! `file-write-create` answers 1 for the per-user temporary directory even
//! where writes there are allowed, so a write counts as denied only when
//! both creating and writing data are.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const SANDBOX_FILTER_NONE: c_int = 0;
const SANDBOX_FILTER_PATH: c_int = 1;
/// Ask without logging a sandbox violation report.
const SANDBOX_CHECK_NO_REPORT: c_int = 0x4000_0000;

extern "C" {
    fn sandbox_check(pid: c_int, operation: *const c_char, filter: c_int, ...) -> c_int;
}

fn pid() -> c_int {
    c_int::try_from(std::process::id()).unwrap_or(-1)
}

/// Whether the sandbox around this process denies outbound network.
pub fn denies_network() -> bool {
    // SAFETY: the operation is a NUL-terminated literal and the filter
    // takes no further argument.
    let answer = unsafe {
        sandbox_check(
            pid(),
            c"network-outbound".as_ptr(),
            SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT,
        )
    };
    answer == 1
}

/// Whether the sandbox around this process denies writing in the existing
/// directory `directory`. Anything else is never reported as denied.
pub fn denies_write(directory: &Path) -> bool {
    if !directory.is_dir() {
        return false;
    }
    let Ok(path) = CString::new(directory.as_os_str().as_bytes()) else {
        return false;
    };
    [c"file-write-create", c"file-write-data"]
        .iter()
        .all(|operation| denies_path(operation, &path))
}

fn denies_path(operation: &CStr, path: &CStr) -> bool {
    // SAFETY: both strings are NUL-terminated and outlive the call; the
    // path filter takes exactly one C string.
    let answer = unsafe {
        sandbox_check(
            pid(),
            operation.as_ptr(),
            SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
            path.as_ptr(),
        )
    };
    answer == 1
}

/// The per-user temporary directory the system assigns, whatever
/// `$TMPDIR` says.
pub fn user_temp_dir() -> Option<PathBuf> {
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the buffer is writable for the length passed.
    let length = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length == 0 || length > buffer.len() {
        return None;
    }
    buffer.truncate(length - 1);
    let path = PathBuf::from(OsString::from_vec(buffer));
    path.is_absolute().then_some(path)
}

/// The home directory the account database records for this user, whatever
/// `$HOME` says.
pub fn account_home() -> Option<PathBuf> {
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0 as c_char; 4096];
    // SAFETY: `record` and `buffer` are writable for the sizes passed, and
    // `getpwuid_r` only stores into them.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() {
        return None;
    }
    // SAFETY: on success `record` is initialised and `pw_dir` points into
    // `buffer`, which is still alive.
    let directory = unsafe { record.assume_init_ref().pw_dir };
    if directory.is_null() {
        return None;
    }
    // SAFETY: a non-null `pw_dir` is a NUL-terminated string in `buffer`.
    let home = unsafe { CStr::from_ptr(directory) };
    let path = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
    path.is_absolute().then_some(path)
}
