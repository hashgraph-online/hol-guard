use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

const MAX_BYTES: u64 = 256 * 1024 * 1024;
fn copy(source: &mut File, destination: &mut File, expected: &str) -> io::Result<()> {
    let before = crate::bound_fs::identity(source)?;
    if source.metadata()?.len() > MAX_BYTES {
        return Err(crate::bound_fs::changed());
    }
    source.seek(SeekFrom::Start(0))?;
    let count = io::copy(&mut (&mut *source).take(MAX_BYTES + 1), destination)?;
    destination.sync_all()?;
    if count > MAX_BYTES
        || before != crate::bound_fs::identity(source)?
        || crate::bound_fs::digest_executable(destination, MAX_BYTES as usize)? != expected
    {
        return Err(crate::bound_fs::changed());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn memfd() -> io::Result<File> {
    let raw = unsafe {
        libc::memfd_create(
            c"guard-executable".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
#[cfg(target_os = "linux")]
fn finish(file: &mut File) -> io::Result<()> {
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}
#[cfg(target_os = "linux")]
pub(crate) fn seal_executable(mut source: File, expected: &str) -> io::Result<File> {
    let mut sealed = memfd()?;
    copy(&mut source, &mut sealed, expected)?;
    finish(&mut sealed)?;
    Ok(sealed)
}
#[cfg(target_os = "linux")]
pub(crate) fn seal_bytes(bytes: &[u8], expected: &str) -> io::Result<File> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(crate::bound_fs::changed());
    }
    let mut sealed = memfd()?;
    sealed.write_all(bytes)?;
    if crate::bound_fs::digest_executable(&mut sealed, MAX_BYTES as usize)? != expected {
        return Err(crate::bound_fs::changed());
    }
    finish(&mut sealed)?;
    Ok(sealed)
}
#[cfg(target_os = "macos")]
static ROOT_MODE_OWNERS: std::sync::Mutex<std::collections::BTreeSet<(u64, u64)>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(target_os = "macos")]
struct RootModeLease {
    identity: (u64, u64),
    previous_mode: u32,
}
#[cfg(target_os = "macos")]
impl RootModeLease {
    fn acquire(binding: &crate::bound_fs::Directory) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut owners = ROOT_MODE_OWNERS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let metadata = binding.handle().metadata()?;
        let identity = (metadata.dev(), metadata.ino());
        if owners.contains(&identity) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "runtime image root already has a mode owner",
            ));
        }
        // Snapshot and chmod under the ownership lock; another adopter must
        // never capture the temporary read-only mode as its original mode.
        let previous_mode = metadata.permissions().mode() & 0o7777;
        if unsafe { libc::fchmod(binding.handle().as_raw_fd(), 0o500) } != 0 {
            return Err(io::Error::last_os_error());
        }
        owners.insert(identity);
        Ok(Self {
            identity,
            previous_mode,
        })
    }
}
#[cfg(target_os = "macos")]
impl Drop for RootModeLease {
    fn drop(&mut self) {
        ROOT_MODE_OWNERS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.identity);
    }
}

#[cfg(target_os = "macos")]
pub(crate) struct PinnedImage {
    pub(crate) file: File,
    pub(crate) path: std::path::PathBuf,
    directory: Option<tempfile::TempDir>,
    binding: std::sync::Arc<crate::bound_fs::Directory>,
    mode_lease: Option<RootModeLease>,
}
#[cfg(target_os = "macos")]
impl Drop for PinnedImage {
    fn drop(&mut self) {
        let Some(lease) = self.mode_lease.as_ref() else {
            return;
        };
        if self.binding.verify().is_err() {
            if let Some(directory) = self.directory.take() {
                let _ = directory.keep();
            }
            return;
        }
        // Restore only the held private parent after the foreign group is dead.
        if unsafe {
            libc::fchmod(
                self.binding.handle().as_raw_fd(),
                lease.previous_mode as libc::mode_t,
            )
        } != 0
        {
            if let Some(directory) = self.directory.take() {
                let _ = directory.keep();
            }
            return;
        }
        if let Some(directory) = self.directory.take() {
            let _ = directory.close();
        }
    }
}

#[cfg(target_os = "macos")]
fn on_readonly_root(source: &File) -> io::Result<bool> {
    let root = File::open("/")?;
    let mut root_fs: libc::statfs = unsafe { std::mem::zeroed() };
    let mut source_fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut root_fs) } != 0
        || unsafe { libc::fstatfs(source.as_raw_fd(), &mut source_fs) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let required = (libc::MNT_ROOTFS | libc::MNT_RDONLY) as u32;
    // fsid_t's Darwin ABI is two integers, but libc keeps its fields private.
    let same_fs = unsafe {
        libc::memcmp(
            std::ptr::addr_of!(root_fs.f_fsid).cast(),
            std::ptr::addr_of!(source_fs.f_fsid).cast(),
            std::mem::size_of::<libc::fsid_t>(),
        ) == 0
    };
    Ok(same_fs
        && root_fs.f_flags & required == required
        && source_fs.f_flags & required == required)
}
#[cfg(target_os = "macos")]
pub(crate) fn seal_executable(
    mut source: File,
    expected: &str,
    root: Option<&std::path::Path>,
    source_directory: std::sync::Arc<crate::bound_fs::Directory>,
) -> io::Result<PinnedImage> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if on_readonly_root(&source)? {
        // Apple platform images cannot generally execute after copying. Adopt
        // only the actual read-only system filesystem, never a path allowlist
        // or a caller-mounted read-only volume.
        let mut bytes = [0u8; 1024];
        if unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(crate::bound_fs::changed)?;
        let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]));
        if path.parent() != Some(source_directory.path()) {
            return Err(crate::bound_fs::changed());
        }
        let current = source_directory.open_installed_file(std::path::Path::new(
            path.file_name().ok_or_else(crate::bound_fs::changed)?,
        ))?;
        if crate::bound_fs::identity(&current)? != crate::bound_fs::identity(&source)?
            || crate::bound_fs::digest_executable(&mut source, MAX_BYTES as usize)? != expected
        {
            return Err(crate::bound_fs::changed());
        }
        source_directory.verify()?;
        return Ok(PinnedImage {
            file: source,
            path,
            directory: None,
            binding: source_directory,
            mode_lease: None,
        });
    }
    if let Some(root) = root {
        // This authority comes only from a trusted native caller's captured
        // private root. Adopting avoids an unbudgeted second image copy and
        // preserves Python's captured prefix and Node's executable pathname.
        if root != source_directory.path() {
            return Err(crate::bound_fs::changed());
        }
        let mut bytes = [0u8; 1024];
        if unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(crate::bound_fs::changed)?;
        let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]));
        if path.parent() != Some(root) || source.metadata()?.permissions().mode() & 0o222 != 0 {
            return Err(crate::bound_fs::changed());
        }
        let current = source_directory.open_installed_file(std::path::Path::new(
            path.file_name().ok_or_else(crate::bound_fs::changed)?,
        ))?;
        if crate::bound_fs::identity(&current)? != crate::bound_fs::identity(&source)?
            || crate::bound_fs::digest_executable(&mut source, MAX_BYTES as usize)? != expected
        {
            return Err(crate::bound_fs::changed());
        }
        source_directory.verify()?;
        let mode_lease = RootModeLease::acquire(&source_directory)?;
        return Ok(PinnedImage {
            file: source,
            path,
            directory: None,
            binding: source_directory,
            mode_lease: Some(mode_lease),
        });
    }
    let directory = tempfile::Builder::new()
        .prefix("guard-native-image-")
        .tempdir()?;
    let root = directory.path().canonicalize()?;
    let binding = std::sync::Arc::new(crate::bound_fs::Directory::open(&root)?);
    let path = root.join("image");
    let mut destination = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o500)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    copy(&mut source, &mut destination, expected)?;
    let identity = crate::bound_fs::identity(&destination)?;
    drop(destination);
    let file = crate::bound_fs::open_executable(&path)?;
    if crate::bound_fs::identity(&file)? != identity {
        return Err(crate::bound_fs::changed());
    }
    binding.verify()?;
    let mode_lease = RootModeLease::acquire(&binding)?;
    Ok(PinnedImage {
        file,
        path,
        directory: Some(directory),
        binding,
        mode_lease: Some(mode_lease),
    })
}

#[cfg(all(test, target_os = "macos"))]
#[path = "unix_image_tests.rs"]
mod tests;
