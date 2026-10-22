//! Bounded reads of delivery files.
//!
//! Installed wheels may hard-link their data files, so these reads do not
//! require a single link. They refuse a symlink leaf, anything that is not a
//! regular file, a file over the bound, and a file that changes while read.
//! Callers resolve and check the ancestors of the path before asking.
use std::{fs, io::Read, path::Path};

pub(super) struct Unreadable;

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Unreadable> {
    let linked = fs::symlink_metadata(path).map_err(|_| Unreadable)?;
    if linked.file_type().is_symlink() {
        return Err(Unreadable);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|_| Unreadable)?;
    let before = file.metadata().map_err(|_| Unreadable)?;
    if !before.is_file()
        || usize::try_from(before.len())
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(Unreadable);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(u64::try_from(limit).map_err(|_| Unreadable)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Unreadable)?;
    let after = file.metadata().map_err(|_| Unreadable)?;
    if bytes.len() > limit
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(Unreadable);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
