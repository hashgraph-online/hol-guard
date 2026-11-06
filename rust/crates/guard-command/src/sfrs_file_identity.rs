//! Filesystem identity tuples used for race detection
//! (`file_identity.py`, `full_stat_identity`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs::Metadata;

/// `full_stat_identity`: device, inode, mode, link count, size, modification
/// and change time in nanoseconds, and the Windows file attributes.
#[cfg(unix)]
pub(crate) fn full_stat_identity(metadata: &Metadata) -> [i128; 8] {
    use std::os::unix::fs::MetadataExt;

    let nanoseconds =
        |seconds: i64, fraction: i64| i128::from(seconds) * 1_000_000_000 + i128::from(fraction);
    [
        i128::from(metadata.dev()),
        i128::from(metadata.ino()),
        i128::from(metadata.mode()),
        i128::from(metadata.nlink()),
        i128::from(metadata.size()),
        nanoseconds(metadata.mtime(), metadata.mtime_nsec()),
        nanoseconds(metadata.ctime(), metadata.ctime_nsec()),
        0,
    ]
}

/// `full_stat_identity` from the fields stable `std` exposes on Windows. The
/// volume serial, file index and link count are not available without
/// unstable APIs, so they read as zero and callers must not rely on them.
#[cfg(windows)]
pub(crate) fn full_stat_identity(metadata: &Metadata) -> [i128; 8] {
    use std::os::windows::fs::MetadataExt;

    [
        0,
        0,
        0,
        0,
        i128::from(metadata.file_size()),
        i128::from(metadata.last_write_time()),
        i128::from(metadata.creation_time()),
        i128::from(metadata.file_attributes()),
    ]
}
