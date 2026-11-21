//! A path's 8.3 short form and a short name's long form, as kernel32's
//! `GetShortPathNameW` and `GetLongPathNameW` answer them.
//!
//! Guard writes a Windows hook command with plain tokens only, so a path
//! that would need quoting is spelled by its short name, and a command read
//! back maps each short name to the long path it stands for.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::{GetLongPathNameW, GetShortPathNameW};

type PathForm = unsafe extern "system" fn(*const u16, *mut u16, DWORD) -> DWORD;

fn converted(function: PathForm, path: &str) -> Option<String> {
    if path.contains('\0') {
        return None;
    }
    let mut wide: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().collect();
    wide.push(0);
    // SAFETY: `wide` is NUL-terminated and outlives the call; a null buffer
    // with a zero length only asks for the size the answer needs.
    let size = unsafe { function(wide.as_ptr(), std::ptr::null_mut(), 0) };
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; size as usize];
    // SAFETY: `buffer` holds exactly `size` writable UTF-16 units.
    let written = unsafe { function(wide.as_ptr(), buffer.as_mut_ptr(), size) };
    if written == 0 || written >= size {
        return None;
    }
    buffer.truncate(written as usize);
    OsString::from_wide(&buffer).into_string().ok()
}

/// `path`'s 8.3 short form, or `None` when the volume has none or the path
/// does not exist.
pub fn short_path_name(path: &str) -> Option<String> {
    converted(GetShortPathNameW, path)
}

/// The long path an 8.3 short name stands for, or `None` when it names
/// nothing.
pub fn long_path_name(path: &str) -> Option<String> {
    converted(GetLongPathNameW, path)
}
