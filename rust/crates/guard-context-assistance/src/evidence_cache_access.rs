//! Open modes, the store lock and fault points shared by the Unix and
//! Windows directory layers.
use crate::RuntimeError;
use std::fs::File;

/// How a fixed name below a pinned directory is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Access {
    /// Read an existing file.
    Read,
    /// Read and write an existing file.
    Write,
    /// Read and write, creating the file when it is missing.
    WriteOrCreate,
    /// Write a file that must not exist yet.
    CreateNew,
}

/// A whole-file exclusive lock, released when it is dropped.
#[cfg(unix)]
pub(crate) type Locked = nix::fcntl::Flock<File>;
#[cfg(windows)]
pub(crate) struct Locked(File);
#[cfg(windows)]
impl std::ops::Deref for Locked {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}

/// Take a whole-file exclusive lock without waiting. Another holder makes
/// this `Busy`.
pub(crate) fn lock(file: File) -> Result<Locked, RuntimeError> {
    #[cfg(unix)]
    {
        use nix::fcntl::{Flock, FlockArg};
        Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| RuntimeError::Busy)
    }
    #[cfg(windows)]
    {
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| RuntimeError::Busy)?;
        Ok(Locked(file))
    }
}

#[cfg(test)]
thread_local! { pub(crate) static WRITE_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn boundary(phase: u8) -> Result<(), RuntimeError> {
    if WRITE_FAULT.with(|fault| {
        if fault.get() == phase {
            fault.set(0);
            true
        } else {
            false
        }
    }) {
        Err(RuntimeError::StorageOutcomeUnknown)
    } else {
        Ok(())
    }
}
