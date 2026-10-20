//! Prepare output bindings without effects; open them only in an authorized child.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::bound_fs::{changed, relative_components, Directory};

#[derive(Clone)]
pub struct DeferredOutput {
    directory: Arc<Directory>,
    leaf: CString,
    before: Option<(u64, u64)>,
    truncate: bool,
}

pub(crate) struct ChildOutput {
    pub(crate) directory: OwnedFd,
    leaf: CString,
    before: Option<(u64, u64)>,
    truncate: bool,
}

pub(crate) fn prepare_all(
    outputs: &[DeferredOutput],
    reserved: i32,
) -> io::Result<Vec<ChildOutput>> {
    outputs
        .iter()
        .map(|output| output.child(reserved))
        .collect()
}

impl DeferredOutput {
    pub fn new(directory: Arc<Directory>, leaf: &OsStr, truncate: bool) -> io::Result<Self> {
        if relative_components(Path::new(leaf))?.len() != 1 {
            return Err(changed());
        }
        crate::bound_output::validate_target(&directory, leaf)?;
        let leaf = CString::new(leaf.as_bytes()).map_err(|_| changed())?;
        let before = named(directory.handle().as_raw_fd(), &leaf)?;
        let prepared = Self {
            directory,
            leaf,
            before,
            truncate,
        };
        prepared.verify_before()?;
        Ok(prepared)
    }

    pub(crate) fn verify_before(&self) -> io::Result<()> {
        self.directory.verify()?;
        if named(self.directory.handle().as_raw_fd(), &self.leaf)? != self.before {
            return Err(changed());
        }
        Ok(())
    }

    pub(crate) fn verify_opened(&self, device: u64, inode: u64) -> io::Result<()> {
        self.directory.verify()?;
        if named(self.directory.handle().as_raw_fd(), &self.leaf)? != Some((device, inode)) {
            return Err(changed());
        }
        Ok(())
    }

    pub(crate) fn child(&self, reserved: i32) -> io::Result<ChildOutput> {
        self.verify_before()?;
        let raw = unsafe {
            libc::fcntl(
                self.directory.handle().as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                reserved,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ChildOutput {
            directory: unsafe { OwnedFd::from_raw_fd(raw) },
            leaf: self.leaf.clone(),
            before: self.before,
            truncate: self.truncate,
        })
    }
}

fn named(directory: i32, leaf: &CString) -> io::Result<Option<(u64, u64)>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory,
            leaf.as_ptr(),
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
    let stat = unsafe { stat.assume_init() };
    if !regular(&stat) {
        return Err(changed());
    }
    Ok(Some(object(&stat)))
}

fn regular(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 1
}

fn object(stat: &libc::stat) -> (u64, u64) {
    (
        stat.st_dev as libc::c_ulonglong,
        stat.st_ino as libc::c_ulonglong,
    )
}

impl ChildOutput {
    /// The target currently holds this output's duplicated directory. Only
    /// stack operations and async-signal-safe syscalls run after fork.
    pub(crate) unsafe fn open_at_target(&self, target: i32, acknowledgment: i32) -> bool {
        let mut flags =
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_APPEND;
        if self.before.is_none() {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
        let file = unsafe { libc::openat(target, self.leaf.as_ptr(), flags, 0o666) };
        if file < 0 {
            return false;
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file, stat.as_mut_ptr()) } != 0
            || unsafe {
                libc::fstatat(
                    target,
                    self.leaf.as_ptr(),
                    current.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
        {
            unsafe {
                libc::close(file);
            }
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        let current = unsafe { current.assume_init() };
        if !regular(&stat)
            || !regular(&current)
            || object(&stat) != object(&current)
            || self.before.is_some_and(|before| before != object(&stat))
            || self.truncate && unsafe { libc::ftruncate(file, 0) } != 0
        {
            unsafe {
                libc::close(file);
            }
            return false;
        }
        if unsafe { libc::dup2(file, target) } < 0
            || unsafe { libc::fcntl(target, libc::F_SETFD, 0) } != 0
        {
            unsafe {
                libc::close(file);
            }
            return false;
        }
        unsafe {
            libc::close(file);
        }
        let mut frame = [0u8; 21];
        frame[0] = b'O';
        frame[1..5].copy_from_slice(&(target as u32).to_le_bytes());
        let (device, inode) = object(&stat);
        frame[5..13].copy_from_slice(&device.to_le_bytes());
        frame[13..21].copy_from_slice(&inode.to_le_bytes());
        let mut offset = 0;
        while offset < frame.len() {
            let count = unsafe {
                libc::write(
                    acknowledgment,
                    frame[offset..].as_ptr().cast(),
                    frame.len() - offset,
                )
            };
            if count > 0 {
                offset += count as usize;
            } else if count < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            } else {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
#[path = "deferred_output_tests.rs"]
mod tests;
