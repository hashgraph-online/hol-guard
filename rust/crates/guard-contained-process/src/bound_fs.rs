use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::MetadataExt,
};
use std::path::{Component, Path, PathBuf};
mod directory;
mod operations;
#[path = "promotion.rs"]
mod promotion;

pub fn changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "filesystem binding changed")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    file_id: guard_runtime_windows_process::FileId,
    size: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    changed_sec: i64,
    #[cfg(unix)]
    changed_nsec: i64,
}
impl Identity {
    pub(crate) fn same_object(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(windows)]
        {
            self.file_id == other.file_id
        }
    }
}

pub fn identity(file: &File) -> io::Result<Identity> {
    let metadata = file.metadata()?;
    Ok(Identity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(windows)]
        file_id: guard_runtime_windows_process::handle_file_id(file)?,
        size: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        changed_sec: metadata.ctime(),
        #[cfg(unix)]
        changed_nsec: metadata.ctime_nsec(),
    })
}

/// Opaque object identity for a native parent/contained-child probe. It carries
/// no pathname authority and excludes mutable file contents/timestamps.
pub fn object_token(file: &File) -> io::Result<String> {
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
        bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
        Ok(hex::encode(Sha256::digest(bytes)))
    }
    #[cfg(windows)]
    {
        let id = guard_runtime_windows_process::handle_file_id(file)?;
        Ok(hex::encode(Sha256::digest(format!("{id:?}").as_bytes())))
    }
}

pub struct ReadFile {
    pub bytes: Vec<u8>,
    pub digest: String,
    pub identity: Identity,
}

fn regular(file: &File, executable: bool) -> io::Result<()> {
    #[cfg(not(unix))]
    let _ = executable;
    let m = file.metadata()?;
    if !m.is_file() {
        return Err(changed());
    }
    #[cfg(unix)]
    if !executable && m.nlink() != 1 {
        return Err(changed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(changed());
        }
    }
    Ok(())
}

pub fn read_file(file: &mut File, max_bytes: usize) -> io::Result<ReadFile> {
    read_contents(file, max_bytes, false)
}
pub fn read_executable(file: &mut File, max_bytes: usize) -> io::Result<ReadFile> {
    read_contents(file, max_bytes, true)
}
fn read_contents(file: &mut File, max_bytes: usize, executable: bool) -> io::Result<ReadFile> {
    regular(file, executable)?;
    let before = identity(file)?;
    if before.size > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file byte budget exceeded",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(before.size as usize);
    (&mut *file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes || bytes.len() as u64 != before.size || identity(file)? != before {
        return Err(changed());
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    Ok(ReadFile {
        bytes,
        digest,
        identity: before,
    })
}

pub fn digest_file(file: &mut File, max_bytes: usize) -> io::Result<String> {
    digest_contents(file, max_bytes, false)
}
pub fn digest_executable(file: &mut File, max_bytes: usize) -> io::Result<String> {
    digest_contents(file, max_bytes, true)
}
fn digest_contents(file: &mut File, max_bytes: usize, executable: bool) -> io::Result<String> {
    regular(file, executable)?;
    let before = identity(file)?;
    if before.size > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file byte budget exceeded",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        total = total.checked_add(length).ok_or_else(changed)?;
        if total > max_bytes {
            return Err(changed());
        }
        hash.update(&buffer[..length]);
    }
    if total as u64 != before.size || identity(file)? != before {
        return Err(changed());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hex::encode(hash.finalize()))
}

#[cfg(unix)]
fn cstr(part: &OsStr) -> io::Result<CString> {
    CString::new(part.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

pub(crate) fn relative_components(path: &Path) -> io::Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) if part != "." && part != ".." => {
                components.push(part.to_os_string())
            }
            Component::CurDir if path == Path::new(".") => {}
            _ => return Err(changed()),
        }
    }
    Ok(components)
}

/// A root directory and its ancestry remain pinned for the whole operation.
pub struct Directory {
    path: PathBuf,
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

pub fn open_regular(path: &Path) -> io::Result<File> {
    let parent = path.parent().ok_or_else(changed)?;
    Directory::open(parent)?.open_file(Path::new(path.file_name().ok_or_else(changed)?))
}

pub fn open_executable(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    return guard_runtime_windows_process::open_bound_executable_file(path);
    #[cfg(unix)]
    {
        let parent = Directory::open(path.parent().ok_or_else(changed)?)?;
        let name = cstr(path.file_name().ok_or_else(changed)?)?;
        let file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            ))?)
        };
        regular(&file, true)?;
        Ok(file)
    }
}

#[cfg(unix)]
fn checked_fd(fd: i32) -> io::Result<i32> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}
#[cfg(target_os = "linux")]
fn set_errno(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}
#[cfg(target_os = "linux")]
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
#[cfg(target_os = "macos")]
fn set_errno(value: i32) {
    unsafe {
        *libc::__error() = value;
    }
}
#[cfg(target_os = "macos")]
fn errno() -> i32 {
    unsafe { *libc::__error() }
}
