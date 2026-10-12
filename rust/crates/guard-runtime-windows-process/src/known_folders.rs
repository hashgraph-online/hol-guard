use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use winapi::shared::guiddef::GUID;
use winapi::shared::winerror::S_OK;
use winapi::um::combaseapi::CoTaskMemFree;
use winapi::um::knownfolders::{
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86,
};
use winapi::um::shlobj::{SHGetKnownFolderPath, KF_FLAG_DEFAULT};

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut raw = null_mut();
    // SAFETY: `id` is a valid known-folder GUID and `raw` receives a
    // CoTaskMemAlloc'd, NUL-terminated string that is freed below on every
    // path, including failure, where it may be null.
    let result = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, null_mut(), &mut raw) };
    let path = (result == S_OK && !raw.is_null()).then(|| {
        // SAFETY: On success `raw` points to a NUL-terminated UTF-16 string.
        let length = (0..)
            .take_while(|&index| unsafe { *raw.add(index) } != 0)
            .count();
        // SAFETY: `length` UTF-16 units precede the terminator.
        let units = unsafe { std::slice::from_raw_parts(raw, length) };
        PathBuf::from(OsString::from_wide(units))
    });
    // SAFETY: `raw` was allocated by SHGetKnownFolderPath or is null.
    unsafe { CoTaskMemFree(raw.cast()) };
    path.filter(|path| path.is_absolute())
}

/// Return the Program Files directories as the system reports them.
///
/// The Windows directory is excluded: standard users can create files in
/// descendants such as `Temp` and `System32\Tasks`, so a location there
/// proves nothing about who installed an executable.
///
/// Callers that trust executables by install location must not read these
/// from environment variables such as `ProgramFiles` or `SystemRoot`: the
/// requesting process controls those, and the managed runtime receives a
/// filtered environment that may omit them.
pub fn trusted_install_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for id in [
        &FOLDERID_ProgramFiles,
        &FOLDERID_ProgramFilesX64,
        &FOLDERID_ProgramFilesX86,
    ] {
        if let Some(path) = known_folder(id) {
            if !roots.contains(&path) {
                roots.push(path);
            }
        }
    }
    roots
}
