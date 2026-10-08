use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr, OsString};
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

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        let canonical = {
            let canonical = fs::canonicalize(path)?;
            if canonical != path {
                return Err(changed());
            }
            canonical
        };
        #[cfg(unix)]
        {
            let mut file = unsafe {
                File::from_raw_fd(checked_fd(libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                ))?)
            };
            for part in path.components() {
                if let Component::Normal(part) = part {
                    let name = cstr(part)?;
                    let fd = checked_fd(unsafe {
                        libc::openat(
                            file.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    })?;
                    file = unsafe { File::from_raw_fd(fd) };
                }
            }
            Ok(Self {
                path: canonical,
                file,
            })
        }
        #[cfg(windows)]
        {
            let binding = guard_runtime_windows_process::bind_readonly_directory(path)?;
            Ok(Self {
                path: binding.path().to_path_buf(),
                binding,
            })
        }
        #[cfg(not(any(unix, windows)))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no bound filesystem",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn handle(&self) -> &File {
        #[cfg(unix)]
        return &self.file;
        #[cfg(windows)]
        return self.binding.handle();
    }

    pub fn verify(&self) -> io::Result<()> {
        let current = Self::open(&self.path)?;
        let expected = identity(self.handle())?;
        let actual = identity(current.handle())?;
        #[cfg(unix)]
        if (expected.device, expected.inode) != (actual.device, actual.inode) {
            return Err(changed());
        }
        #[cfg(windows)]
        if expected.file_id != actual.file_id {
            return Err(changed());
        }
        Ok(())
    }

    pub fn directory(&self, path: &Path) -> io::Result<Self> {
        let components = relative_components(path)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let mut file = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    self.file.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                ))?)
            };
            for part in components {
                let name = cstr(&part)?;
                file = unsafe {
                    File::from_raw_fd(checked_fd(libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    ))?)
                };
            }
            let directory = Self {
                path: if path == Path::new(".") {
                    self.path.clone()
                } else {
                    self.path.join(path)
                },
                file,
            };
            directory.verify()?;
            Ok(directory)
        }
        #[cfg(windows)]
        {
            let _ = components;
            Self::open(&self.path.join(path))
        }
    }

    pub fn open_file(&self, path: &Path) -> io::Result<File> {
        let parts = relative_components(path)?;
        let name = parts.last().ok_or_else(changed)?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            self.directory(Path::new("."))?
        } else {
            self.directory(parent)?
        };
        #[cfg(unix)]
        let file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let file = guard_runtime_windows_process::open_bound_regular_file(&parent.path.join(name))?;
        regular(&file, false)?;
        Ok(file)
    }
    /// Installation resources may be hardlinked by a package manager. They are
    /// never used as writable workspace authority.
    pub fn open_installed_file(&self, path: &Path) -> io::Result<File> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let file =
            guard_runtime_windows_process::open_bound_executable_file(&parent.path.join(name))?;
        regular(&file, true)?;
        parent.verify()?;
        Ok(file)
    }

    pub fn read_installed(&self, path: &Path, max_bytes: usize) -> io::Result<ReadFile> {
        let mut file = self.open_installed_file(path)?;
        let read = read_executable(&mut file, max_bytes)?;
        if identity(&self.open_installed_file(path)?)? != read.identity {
            return Err(changed());
        }
        self.verify()?;
        Ok(read)
    }

    pub fn read_link(&self, path: &Path) -> io::Result<(PathBuf, Identity)> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            #[cfg(target_os = "macos")]
            let flags = libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC;
            let file = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    flags,
                ))?)
            };
            if !file.metadata()?.file_type().is_symlink() {
                return Err(changed());
            }
            let before = identity(&file)?;
            let mut bytes = [0u8; 4097];
            let count = unsafe {
                libc::readlinkat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if count <= 0 || count as usize >= bytes.len() {
                return Err(changed());
            }
            let current = unsafe {
                File::from_raw_fd(checked_fd(libc::openat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    flags,
                ))?)
            };
            if identity(&current)? != before || identity(&file)? != before {
                return Err(changed());
            }
            parent.verify()?;
            Ok((
                PathBuf::from(OsString::from_vec(bytes[..count as usize].to_vec())),
                before,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0220_0000)
                .open(parent.path.join(name))?;
            let before = identity(&file)?;
            let target = fs::read_link(parent.path.join(name))?;
            if identity(&file)? != before {
                return Err(changed());
            }
            parent.verify()?;
            Ok((target, before))
        }
    }

    pub fn read(&self, path: &Path, max_bytes: usize) -> io::Result<ReadFile> {
        let mut file = self.open_file(path)?;
        let read = read_file(&mut file, max_bytes)?;
        let current = self.open_file(path)?;
        if identity(&current)? != read.identity {
            return Err(changed());
        }
        self.verify()?;
        Ok(read)
    }

    /// Private staged output only. This does not publish into a live workspace.
    /// An already authorized output leaf is written through its verified handle,
    /// so LPAC needs no directory-create/delete grant.
    pub fn write_existing(
        &self,
        path: &Path,
        expected: (&Identity, &str),
        bytes: &[u8],
    ) -> io::Result<()> {
        relative_components(path)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let mut file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            ))?)
        };
        #[cfg(windows)]
        let mut file = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(parent.path.join(name))?
        };
        let before = read_file(&mut file, 16 * 1024 * 1024)?;
        let path_matches = || -> io::Result<bool> {
            #[cfg(unix)]
            {
                Ok(identity(&parent.open_file(Path::new(name))?)?.same_object(expected.0))
            }
            #[cfg(windows)]
            {
                // Attribute-only identity queries share the held writer's
                // access without releasing its write/delete exclusion.
                let (file_id, _) =
                    guard_runtime_windows_process::regular_file_id(&parent.path.join(name), false)?;
                Ok(file_id == expected.0.file_id)
            }
        };
        if before.identity != *expected.0 || before.digest != expected.1 || !path_matches()? {
            return Err(changed());
        }
        parent.verify()?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()?;
        if !identity(&file)?.same_object(expected.0) || !path_matches()? {
            return Err(changed());
        }
        parent.verify()
    }

    pub fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        relative_components(path)?;
        if path == Path::new(".") {
            self.verify()?;
            return self.handle().metadata();
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent)?;
        let metadata =
            fs::symlink_metadata(parent.path.join(path.file_name().ok_or_else(changed)?))?;
        parent.verify()?;
        Ok(metadata)
    }

    pub fn entries(&self, path: &Path, remaining: usize) -> io::Result<Vec<OsString>> {
        let directory = self.directory(path)?;
        let mut names = Vec::new();
        #[cfg(unix)]
        {
            let raw = checked_fd(unsafe { libc::dup(directory.file.as_raw_fd()) })?;
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                unsafe {
                    libc::close(raw);
                }
                return Err(io::Error::last_os_error());
            }
            struct Stream(*mut libc::DIR);
            impl Drop for Stream {
                fn drop(&mut self) {
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Stream(stream);
            loop {
                set_errno(0);
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = errno();
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    break;
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if names.len() >= remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory entry budget exceeded",
                    ));
                }
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        #[cfg(windows)]
        {
            // All ancestry handles deny delete sharing, so this pathname still
            // names the held directory throughout enumeration.
            for entry in fs::read_dir(directory.path())? {
                if names.len() >= remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory entry budget exceeded",
                    ));
                }
                names.push(entry?.file_name());
            }
        }
        directory.verify()?;
        names.sort();
        Ok(names)
    }

    pub fn mkdir_all(&self, path: &Path) -> io::Result<()> {
        let mut relative = PathBuf::new();
        for part in relative_components(path)? {
            let directory = self.directory(if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                &relative
            })?;
            #[cfg(unix)]
            {
                let status = unsafe {
                    libc::mkdirat(directory.file.as_raw_fd(), cstr(&part)?.as_ptr(), 0o700)
                };
                if status != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(windows)]
            match fs::create_dir(directory.path.join(&part)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            relative.push(part);
            self.directory(&relative)?;
        }
        self.verify()
    }

    /// A new leaf is never opened through a symlink or an existing pathname.
    pub fn create(&self, path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        let mut file = unsafe {
            File::from_raw_fd(checked_fd(libc::openat(
                parent.file.as_raw_fd(),
                cstr(name)?.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                if executable { 0o500 } else { 0o600 },
            ))?)
        };
        #[cfg(windows)]
        let mut file = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(0x0020_0000)
                .open(parent.path.join(name))?
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        parent.verify()?;
        Ok(())
    }

    /// Transactional publication validates the displaced target. An exchange
    /// failure may briefly expose output bytes; raced user objects are retained
    /// in a private recovery directory, never removed by recursive cleanup.
    pub fn atomic_replace(
        &self,
        path: &Path,
        expected: Option<(&Identity, &str)>,
        bytes: &[u8],
    ) -> io::Result<()> {
        promotion::replace(self, path, expected, bytes)
    }
    pub fn atomic_remove(&self, path: &Path, expected: (&Identity, &str)) -> io::Result<()> {
        promotion::remove(self, path, expected)
    }

    pub fn atomic_remove_directory(&self, path: &Path, expected: &Identity) -> io::Result<()> {
        promotion::remove_directory(self, path, expected)
    }

    /// Cleanup is restricted to this held private tree. Displaced user objects
    /// are retained by the conditional native removal primitives on a race.
    pub fn remove_tree(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let mode = self.handle().metadata()?.mode() & 0o7777;
            if mode & 0o700 != 0o700
                && unsafe {
                    libc::fchmod(self.handle().as_raw_fd(), (mode | 0o700) as libc::mode_t)
                } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        for name in self.entries(Path::new("."), 50_000)? {
            let path = Path::new(&name);
            let metadata = self.metadata(path)?;
            if metadata.file_type().is_symlink() {
                return Err(changed());
            }
            if metadata.is_dir() {
                let child = self.directory(path)?;
                let expected = identity(child.handle())?;
                child.remove_tree()?;
                drop(child);
                self.atomic_remove_directory(path, &expected)?;
            } else if metadata.is_file() {
                let file = self.read_installed(path, 256 * 1024 * 1024)?;
                self.atomic_remove(path, (&file.identity, &file.digest))?;
            } else {
                return Err(changed());
            }
        }
        Ok(())
    }

    pub fn unlink(&self, path: &Path, directory: bool) -> io::Result<()> {
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.directory(parent_path)?;
        let name = path.file_name().ok_or_else(changed)?;
        #[cfg(unix)]
        {
            let result = unsafe {
                libc::unlinkat(
                    parent.file.as_raw_fd(),
                    cstr(name)?.as_ptr(),
                    if directory { libc::AT_REMOVEDIR } else { 0 },
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(windows)]
        if directory {
            fs::remove_dir(parent.path.join(name))?;
        } else {
            fs::remove_file(parent.path.join(name))?;
        }
        parent.verify()
    }
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
