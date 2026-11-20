//! The raw directory facts behind `windows-trusted-directories --stdin`:
//! the Windows and System32 directories the kernel reports and the real,
//! final path of a directory or regular file that is not a reparse point.

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use winapi::um::sysinfoapi::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use winapi::um::winnt::FILE_ATTRIBUTE_REPARSE_POINT;

/// More than any directory path Windows reports.
const PATH_BUFFER_CHARS: usize = 32_768;

/// The Windows directory as the kernel reports it, never as the requesting
/// environment spells it (`SystemRoot`, `windir`).
pub fn kernel_windows_directory() -> Option<String> {
    // SAFETY: The buffer holds `size` writable UTF-16 units.
    kernel_directory(|buffer, size| unsafe { GetSystemWindowsDirectoryW(buffer, size) })
}

/// The native System32 directory as the kernel reports it.
pub fn kernel_system_directory() -> Option<String> {
    // SAFETY: The buffer holds `size` writable UTF-16 units.
    kernel_directory(|buffer, size| unsafe { GetSystemDirectoryW(buffer, size) })
}

fn kernel_directory(read: impl FnOnce(*mut u16, u32) -> u32) -> Option<String> {
    let mut buffer = vec![0u16; PATH_BUFFER_CHARS];
    let length = read(buffer.as_mut_ptr(), buffer.len() as u32) as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    String::from_utf16(&buffer[..length]).ok()
}

/// The final path of `path` when it is a directory and not itself a
/// reparse point.
pub fn real_directory(path: &str) -> Option<String> {
    real_path(path, |metadata| metadata.is_dir())
}

/// The final path of `path` when it is a regular file and not itself a
/// reparse point.
pub fn real_regular_file(path: &str) -> Option<String> {
    real_path(path, |metadata| metadata.is_file())
}

fn real_path(path: &str, kind: impl FnOnce(&std::fs::Metadata) -> bool) -> Option<String> {
    let metadata = std::fs::symlink_metadata(Path::new(path)).ok()?;
    if !kind(&metadata) || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return None;
    }
    let resolved = std::fs::canonicalize(path).ok()?;
    Some(ordinary_path(resolved.to_str()?))
}

/// `text` without its `\\?\` prefix when the ordinary spelling still fits
/// `MAX_PATH`, as `ntpath.realpath` answers; a longer path keeps the prefix
/// so callers can still open it.
fn ordinary_path(text: &str) -> String {
    const MAX_PATH: usize = 260;
    let ordinary = if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(local) = text.strip_prefix(r"\\?\") {
        local.to_owned()
    } else {
        return text.to_owned();
    };
    if ordinary.encode_utf16().count() < MAX_PATH {
        ordinary
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_kernel_directories() {
        let windows = kernel_windows_directory().unwrap();
        let system = kernel_system_directory().unwrap();
        assert!(system
            .to_lowercase()
            .starts_with(&format!("{}\\", windows.to_lowercase())));
        let real = real_directory(&system).unwrap();
        assert!(!real.starts_with(r"\\?\"));
        assert!(real_regular_file(&system).is_none());
        let cmd = real_regular_file(&format!("{system}\\cmd.exe")).unwrap();
        assert!(cmd.to_lowercase().ends_with("\\cmd.exe"));
        assert!(real_directory(&format!("{system}\\cmd.exe")).is_none());
        assert!(real_directory(&format!("{system}\\no-such-guard-directory")).is_none());
    }

    #[test]
    fn long_paths_keep_their_extended_prefix() {
        assert_eq!(ordinary_path(r"\\?\C:\Users\guard"), r"C:\Users\guard");
        assert_eq!(
            ordinary_path(r"\\?\UNC\server\share\guard"),
            r"\\server\share\guard"
        );
        assert_eq!(ordinary_path(r"C:\Users\guard"), r"C:\Users\guard");
        let long = format!(r"\\?\C:\{}", "a".repeat(300));
        assert_eq!(ordinary_path(&long), long);
        let long_unc = format!(r"\\?\UNC\server\share\{}", "a".repeat(300));
        assert_eq!(ordinary_path(&long_unc), long_unc);
    }
}
