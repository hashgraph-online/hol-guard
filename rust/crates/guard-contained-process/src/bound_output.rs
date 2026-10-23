//! Native-owned output handles. Authorization remains the caller's gate.
//!
//! The caller checks policy against this held directory and literal leaf before
//! opening it. No truncation happens until the no-follow descriptor is verified
//! as the same regular, singly-linked target. Shell redirections then inherit
//! this handle instead of resolving the pathname again.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use crate::bound_fs::{changed, relative_components, Directory};

pub struct Output {
    directory: Arc<Directory>,
    leaf: OsString,
    file: File,
}

/// Inspect a target without opening, creating, truncating or following it.
pub fn validate_target(directory: &Directory, leaf: &OsStr) -> io::Result<()> {
    if relative_components(Path::new(leaf))?.len() != 1 {
        return Err(changed());
    }
    directory.verify()?;
    let name = CString::new(leaf.as_bytes()).map_err(|_| changed())?;
    if lookup(directory, &name)?.is_some_and(|stat| !regular_single_link(&stat)) {
        return Err(unsafe_output());
    }
    directory.verify()
}

impl Output {
    /// Opening may create/truncate the reviewed output. Call only within the
    /// authenticated launch reservation, after current policy permits effects.
    pub fn open(directory: Arc<Directory>, leaf: &OsStr, truncate: bool) -> io::Result<Self> {
        validate_target(&directory, leaf)?;
        if relative_components(Path::new(leaf))?.len() != 1 {
            return Err(changed());
        }
        let name = CString::new(leaf.as_bytes()).map_err(|_| changed())?;
        directory.verify()?;
        let before = lookup(&directory, &name)?;
        if before
            .as_ref()
            .is_some_and(|stat| !regular_single_link(stat))
        {
            return Err(unsafe_output());
        }
        let mut flags =
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_APPEND;
        if before.is_none() {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
        let raw =
            unsafe { libc::openat(directory.handle().as_raw_fd(), name.as_ptr(), flags, 0o666) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        let current = lookup(&directory, &name)?.ok_or_else(changed)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !regular_single_link(&current)
            || current.st_dev as u64 != metadata.dev()
            || current.st_ino as u64 != metadata.ino()
            || before.as_ref().is_some_and(|previous| {
                previous.st_dev != current.st_dev || previous.st_ino != current.st_ino
            })
        {
            return Err(unsafe_output());
        }
        directory.verify()?;
        if truncate {
            file.set_len(0)?;
        }
        Ok(Self {
            directory,
            leaf: leaf.to_owned(),
            file,
        })
    }

    /// Recheck path/link bindings before releasing the frozen source frame.
    pub fn verify(&self) -> io::Result<()> {
        self.directory.verify()?;
        let name = CString::new(self.leaf.as_bytes()).map_err(|_| changed())?;
        let current = lookup(&self.directory, &name)?.ok_or_else(changed)?;
        let metadata = self.file.metadata()?;
        if !regular_single_link(&current)
            || metadata.nlink() != 1
            || current.st_dev as u64 != metadata.dev()
            || current.st_ino as u64 != metadata.ino()
        {
            return Err(unsafe_output());
        }
        Ok(())
    }

    pub fn try_clone_file(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}

fn lookup(directory: &Directory, name: &CString) -> io::Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            directory.handle().as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    Ok(Some(unsafe { stat.assume_init() }))
}

fn regular_single_link(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 1
}

fn unsafe_output() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "output target is not a bound regular single-link file",
    )
}

#[cfg(test)]
#[path = "bound_output_tests.rs"]
mod tests;
