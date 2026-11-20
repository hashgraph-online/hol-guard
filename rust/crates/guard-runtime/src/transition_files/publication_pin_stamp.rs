//! The file identity a path's `lstat` and its open handle's `fstat` agree on,
//! ported from `descriptor_fingerprint`, and the no-follow open that reads it.
//!
//! On Windows the two Python reads disagree on creation time and on the
//! execute bits, so the identity there is the volume, the file index, the size
//! and the last write.

use std::fs;
use std::io;
use std::path::Path;

/// One identity; two reads of the same file are equal.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Stamp(Vec<String>);

impl Stamp {
    /// The identity as JSON, for a comparison another op makes.
    pub(super) fn to_value(&self) -> serde_json::Value {
        serde_json::Value::from(self.0.clone())
    }
}

/// What the pinned file reports beside its identity.
pub(super) struct Facts {
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) size: u64,
    pub(super) mtime_ns: i128,
}

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    use super::{fs, io, Facts, Path, Stamp};

    fn stamp(metadata: &fs::Metadata) -> Stamp {
        Stamp(vec![
            metadata.dev().to_string(),
            metadata.ino().to_string(),
            metadata.size().to_string(),
            metadata.mode().to_string(),
            metadata.uid().to_string(),
            metadata.gid().to_string(),
            mtime_ns(metadata).to_string(),
            ctime_ns(metadata).to_string(),
        ])
    }

    fn mtime_ns(metadata: &fs::Metadata) -> i128 {
        i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
    }

    fn ctime_ns(metadata: &fs::Metadata) -> i128 {
        i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec())
    }

    /// `os.lstat`: a link at the leaf is read itself.
    pub(in super::super) fn of_path(path: &Path) -> io::Result<Stamp> {
        Ok(stamp(&fs::symlink_metadata(path)?))
    }

    /// `os.fstat` of the open file.
    pub(in super::super) fn of_file(file: &fs::File) -> io::Result<Stamp> {
        Ok(stamp(&file.metadata()?))
    }

    /// `os.open(path, ARTIFACT_READ_FLAGS)`: read-only, never through a link.
    /// `O_NONBLOCK` keeps a FIFO swapped in after admission from blocking the
    /// open past the pin's deadline; the descriptor's own identity, which
    /// carries the file type, then refuses it.
    pub(in super::super) fn open(path: &Path) -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    /// `os.stat(path)`: the size and `st_mtime_ns` of the file the name reaches.
    pub(in super::super) fn observed(path: &Path) -> io::Result<(u64, i128)> {
        let metadata = fs::metadata(path)?;
        Ok((metadata.size(), mtime_ns(&metadata)))
    }

    pub(in super::super) fn facts(file: &fs::File) -> io::Result<Facts> {
        let metadata = file.metadata()?;
        Ok(Facts {
            mode: metadata.mode(),
            uid: metadata.uid(),
            size: metadata.size(),
            mtime_ns: mtime_ns(&metadata),
        })
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::fs::MetadataExt;

    use super::{fs, io, Facts, Path, Stamp};

    /// `FILE_FLAG_OPEN_REPARSE_POINT`, so a link at the leaf is opened as the
    /// reparse point it is and the regular-file check below refuses it.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// 100ns ticks between 1601-01-01 and the Unix epoch.
    const EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    fn stamp(id: String, size: u64, written: u64) -> Stamp {
        Stamp(vec![id, size.to_string(), written.to_string()])
    }

    pub(in super::super) fn of_path(path: &Path) -> io::Result<Stamp> {
        let (id, _) = guard_runtime_windows_process::regular_file_id(path, false)?;
        let state = guard_runtime_windows_process::link_stat(path)?;
        Ok(stamp(id.to_hex(), state.size, state.last_write_time))
    }

    pub(in super::super) fn of_file(file: &fs::File) -> io::Result<Stamp> {
        let id = guard_runtime_windows_process::handle_file_id(file)?;
        let metadata = file.metadata()?;
        Ok(stamp(
            id.to_hex(),
            metadata.file_size(),
            metadata.last_write_time(),
        ))
    }

    pub(in super::super) fn open(path: &Path) -> io::Result<fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(in super::super) fn observed(path: &Path) -> io::Result<(u64, i128)> {
        let metadata = fs::metadata(path)?;
        Ok((
            metadata.file_size(),
            (i128::from(metadata.last_write_time()) - EPOCH_TICKS) * 100,
        ))
    }

    /// Python reports no owner on Windows, and a read-only file as `0o444`.
    pub(in super::super) fn facts(file: &fs::File) -> io::Result<Facts> {
        let metadata = file.metadata()?;
        let mode = if metadata.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        Ok(Facts {
            mode,
            uid: 0,
            size: metadata.file_size(),
            mtime_ns: (i128::from(metadata.last_write_time()) - EPOCH_TICKS) * 100,
        })
    }
}

pub(super) use platform::{facts, observed, of_file, of_path, open};
