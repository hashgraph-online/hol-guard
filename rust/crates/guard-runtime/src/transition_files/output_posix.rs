//! `safe_output` on POSIX: descriptor-relative publish and removal.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat, OFlag};
use nix::sys::stat::{fchmod, mkdirat, Mode};
use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

use super::random_hex;

fn refused(message: String) -> std::io::Error {
    std::io::Error::other(message)
}

/// `_trusted_system_link`: a root-owned link in a directory only root may
/// change, such as `/tmp` on macOS.
fn trusted_system_link(path: &Path) -> bool {
    let (Ok(link), Some(parent)) = (std::fs::symlink_metadata(path), path.parent()) else {
        return false;
    };
    std::fs::symlink_metadata(parent)
        .is_ok_and(|parent| link.uid() == 0 && parent.uid() == 0 && parent.mode() & 0o022 == 0)
}

/// `_normalized_output_path`: trusted system links resolved, the first
/// missing directory ending the walk.
fn normalized(path: &Path) -> std::io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| refused(format!("output path has no name: {}", path.display())))?;
    let parent = path
        .parent()
        .ok_or_else(|| refused(format!("output path has no parent: {}", path.display())))?;
    let mut components = parent.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refused(format!(
            "output path is not absolute: {}",
            path.display()
        )));
    }
    let mut current = PathBuf::from("/");
    let parts: Vec<_> = components.collect();
    for (index, part) in parts.iter().enumerate() {
        let candidate = current.join(part);
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut rest = candidate;
                rest.extend(parts[index + 1..].iter());
                return Ok(rest.join(name));
            }
            Err(error) => return Err(error),
            Ok(meta) if meta.file_type().is_symlink() => {
                if !trusted_system_link(&candidate) {
                    return Err(refused(format!(
                        "refusing symlinked output directory: {}",
                        candidate.display()
                    )));
                }
                current = std::fs::canonicalize(&candidate)?;
            }
            Ok(_) => current = candidate,
        }
    }
    Ok(current.join(name))
}

const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW);

/// Opens each directory of `parent` without following a link. A missing
/// directory is created when `create` is set; otherwise the walk answers
/// `None`.
fn descend(parent: &Path, create: bool) -> std::io::Result<Option<OwnedFd>> {
    let mut directory = open("/", DIRECTORY, Mode::empty())?;
    for component in parent.components().skip(1) {
        let Component::Normal(part) = component else {
            return Err(refused(format!(
                "output path is not normal: {}",
                parent.display()
            )));
        };
        directory = match openat(&directory, part, DIRECTORY, Mode::empty()) {
            Ok(child) => child,
            Err(Errno::ENOENT) if create => {
                match mkdirat(&directory, part, Mode::from_bits_truncate(0o755)) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                openat(&directory, part, DIRECTORY, Mode::empty())?
            }
            Err(Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    }
    Ok(Some(directory))
}

/// `write_bytes_atomic_no_follow`.
pub(crate) fn write_no_follow(path: &Path, payload: &[u8], mode: u32) -> std::io::Result<()> {
    let target = normalized(path)?;
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(refused(format!(
            "output path is invalid: {}",
            path.display()
        )));
    };
    let directory =
        descend(parent, true)?.ok_or_else(|| refused("output parent vanished".into()))?;
    let temporary = format!(".{}.{}", name.to_string_lossy(), random_hex()?);
    let permissions = Mode::from_bits_truncate(mode as nix::libc::mode_t);
    let create =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let written = openat(&directory, temporary.as_str(), create, permissions)
        .map_err(std::io::Error::from)
        .and_then(|descriptor| {
            let mut file = std::fs::File::from(descriptor);
            fchmod(&file, permissions)?;
            file.write_all(payload)?;
            fsync(&file)?;
            drop(file);
            renameat(&directory, temporary.as_str(), &directory, name)?;
            fsync(&directory).map_err(std::io::Error::from)
        });
    if written.is_err() {
        let _ = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    written
}

/// `remove_file_no_follow`.
pub(crate) fn remove_no_follow(path: &Path) -> std::io::Result<()> {
    let target = normalized(path)?;
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(refused(format!(
            "output path is invalid: {}",
            path.display()
        )));
    };
    let Some(directory) = descend(parent, false)? else {
        return Ok(());
    };
    match unlinkat(&directory, name, UnlinkatFlags::NoRemoveDir) {
        Ok(()) => fsync(&directory).map_err(std::io::Error::from),
        Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
