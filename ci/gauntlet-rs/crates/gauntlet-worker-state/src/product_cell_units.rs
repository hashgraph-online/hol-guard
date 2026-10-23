//! Read-only inventory of Python product-cell systemd units. They are siblings
//! of the inert Rust probe cgroup, so a future worker must account for them
//! separately before claiming whole-job descendant cleanup.

use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;
use std::fmt;
use std::os::fd::OwnedFd;

const SYSTEM_SLICE: &str = "/sys/fs/cgroup/system.slice";
const PREFIX: &[u8] = b"hol-product-cell-";
const SUFFIX: &[u8] = b".service";
const MAX_UNITS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductCellScanError {
    RootRequired,
    Unavailable,
    UnsafeParent,
    UnsafeUnit,
    UnexpectedUnitName,
    TooManyUnits,
    ExistingUnits,
}

impl fmt::Display for ProductCellScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux Root required for product-cell inventory",
            Self::Unavailable => "system.slice product-cell inventory unavailable",
            Self::UnsafeParent => "system.slice directory identity or ownership changed",
            Self::UnsafeUnit => "product-cell unit identity or ownership is unsafe",
            Self::UnexpectedUnitName => "unexpected hol-product-cell unit name",
            Self::TooManyUnits => "product-cell unit inventory exceeds fixed bound",
            Self::ExistingUnits => "product-cell units already exist; inspect before new work",
        })
    }
}

impl std::error::Error for ProductCellScanError {}

fn trusted_directory(stat: &Stat, expected_uid: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == expected_uid
        && stat.st_mode & 0o022 == 0
}

fn same_identity(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn valid_name(name: &[u8]) -> bool {
    name.len() == PREFIX.len() + 32 + SUFFIX.len()
        && name.starts_with(PREFIX)
        && name.ends_with(SUFFIX)
        && name[PREFIX.len()..PREFIX.len() + 32]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(crate) fn scan_at(
    parent: &OwnedFd,
    expected_uid: u32,
) -> Result<Vec<String>, ProductCellScanError> {
    let original = fstat(parent).map_err(|_| ProductCellScanError::Unavailable)?;
    if !trusted_directory(&original, expected_uid) {
        return Err(ProductCellScanError::UnsafeParent);
    }
    let mut entries = Dir::read_from(parent).map_err(|_| ProductCellScanError::Unavailable)?;
    let mut units = Vec::new();
    for entry in &mut entries {
        let entry = entry.map_err(|_| ProductCellScanError::Unavailable)?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if !bytes.starts_with(PREFIX) {
            continue;
        }
        if !valid_name(bytes) {
            return Err(ProductCellScanError::UnexpectedUnitName);
        }
        if units.len() == MAX_UNITS {
            return Err(ProductCellScanError::TooManyUnits);
        }
        let descriptor = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProductCellScanError::UnsafeUnit)?;
        let held = fstat(&descriptor).map_err(|_| ProductCellScanError::UnsafeUnit)?;
        let visible = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ProductCellScanError::UnsafeUnit)?;
        if !trusted_directory(&held, expected_uid) || !same_identity(&held, &visible) {
            return Err(ProductCellScanError::UnsafeUnit);
        }
        units.push(
            std::str::from_utf8(bytes)
                .map_err(|_| ProductCellScanError::UnexpectedUnitName)?
                .to_owned(),
        );
    }
    let after = fstat(parent).map_err(|_| ProductCellScanError::Unavailable)?;
    if !same_identity(&original, &after) {
        return Err(ProductCellScanError::UnsafeParent);
    }
    units.sort_unstable();
    Ok(units)
}

/// Point-in-time inventory only. This does not prevent a new sibling unit
/// appearing after the scan and cannot authorize worker dispatch or cleanup.
pub fn observe_product_cell_units() -> Result<Vec<String>, ProductCellScanError> {
    if geteuid().as_raw() != 0 {
        return Err(ProductCellScanError::RootRequired);
    }
    let parent = open(
        SYSTEM_SLICE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductCellScanError::Unavailable)?;
    let units = scan_at(&parent, 0)?;
    let visible = open(
        SYSTEM_SLICE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductCellScanError::UnsafeParent)?;
    let held = fstat(&parent).map_err(|_| ProductCellScanError::UnsafeParent)?;
    let reopened = fstat(&visible).map_err(|_| ProductCellScanError::UnsafeParent)?;
    if !same_identity(&held, &reopened) {
        return Err(ProductCellScanError::UnsafeParent);
    }
    Ok(units)
}

/// Future admission input: an existing product cell is uncertainty, even if
/// its cgroup currently reports zero tasks. The active Python worker does not
/// call this function.
pub fn require_no_product_cell_units() -> Result<(), ProductCellScanError> {
    if observe_product_cell_units()?.is_empty() {
        Ok(())
    } else {
        Err(ProductCellScanError::ExistingUnits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn exact_unit_names_are_sorted_and_unrelated_units_ignored() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for hex in ["b", "a"] {
            let unit = root
                .path()
                .join(format!("hol-product-cell-{}.service", hex.repeat(32)));
            fs::create_dir(&unit).unwrap();
            fs::set_permissions(&unit, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::create_dir(root.path().join("other.service")).unwrap();
        let parent = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            scan_at(&parent, geteuid().as_raw()).unwrap(),
            vec![
                format!("hol-product-cell-{}.service", "a".repeat(32)),
                format!("hol-product-cell-{}.service", "b".repeat(32)),
            ]
        );
    }

    #[test]
    fn malformed_or_symlinked_product_unit_refuses_inventory() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::create_dir(root.path().join("hol-product-cell-short.service")).unwrap();
        assert_eq!(
            scan_at(&parent, geteuid().as_raw()),
            Err(ProductCellScanError::UnexpectedUnitName)
        );
        fs::remove_dir(root.path().join("hol-product-cell-short.service")).unwrap();
        symlink(
            root.path(),
            root.path()
                .join(format!("hol-product-cell-{}.service", "a".repeat(32))),
        )
        .unwrap();
        assert_eq!(
            scan_at(&parent, geteuid().as_raw()),
            Err(ProductCellScanError::UnsafeUnit)
        );
    }
}
