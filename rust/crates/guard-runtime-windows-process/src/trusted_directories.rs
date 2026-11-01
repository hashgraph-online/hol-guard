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
    let text = resolved.to_str()?;
    Some(if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(text).to_owned()
    })
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
}
