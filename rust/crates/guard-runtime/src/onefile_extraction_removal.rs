//! Deletes one extraction directory with the entries a sweep recognises it
//! by removed last: everything else first, then the Guard package directory,
//! then the owner marker. A sweep killed part way through therefore leaves a
//! directory that still carries its marker or package directory, which the
//! next sweep reclaims.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn remove_extraction_dir(
    path: &Path,
    marker_name: &str,
    package_name: &str,
) -> io::Result<()> {
    for entry in removal_order(path, marker_name, package_name)? {
        remove_entry(&entry)?;
    }
    fs::remove_dir(path)
}

/// The directory's entries in deletion order.
fn removal_order(path: &Path, marker_name: &str, package_name: &str) -> io::Result<Vec<PathBuf>> {
    let rank = |entry: &Path| match entry.file_name().and_then(|name| name.to_str()) {
        Some(name) if name == marker_name => 2,
        Some(name) if name == package_name => 1,
        _ => 0,
    };
    let mut entries = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| rank(entry));
    Ok(entries)
}

fn remove_entry(entry: &Path) -> io::Result<()> {
    let kind = fs::symlink_metadata(entry)?.file_type();
    if kind.is_dir() {
        return fs::remove_dir_all(entry);
    }
    match fs::remove_file(entry) {
        // A Windows directory symlink is removed as a directory.
        Err(_) if kind.is_symlink() => fs::remove_dir(entry),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = ".owner.json";
    const PACKAGE: &str = "package";

    fn plant(root: &Path) -> PathBuf {
        let directory = root.join("_MEIabcd");
        fs::create_dir_all(directory.join(PACKAGE).join("guard")).unwrap();
        fs::create_dir_all(directory.join("lib")).unwrap();
        fs::write(directory.join(PACKAGE).join("guard").join("a.py"), b"a").unwrap();
        fs::write(directory.join("libpython"), b"x").unwrap();
        fs::write(directory.join("zz"), b"y").unwrap();
        fs::write(directory.join(MARKER), b"{}").unwrap();
        directory
    }

    #[test]
    fn the_marker_and_package_directory_are_deleted_last() {
        let root = tempfile::tempdir().unwrap();
        let directory = plant(root.path());
        let order = removal_order(&directory, MARKER, PACKAGE).unwrap();
        let names: Vec<_> = order
            .iter()
            .map(|entry| entry.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(&names[names.len() - 2..], [PACKAGE, MARKER]);
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn the_whole_directory_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let directory = plant(root.path());
        remove_extraction_dir(&directory, MARKER, PACKAGE).unwrap();
        assert!(fs::symlink_metadata(&directory).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_removed_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"k").unwrap();
        let directory = plant(root.path());
        std::os::unix::fs::symlink(outside.path(), directory.join("link")).unwrap();
        remove_extraction_dir(&directory, MARKER, PACKAGE).unwrap();
        assert!(outside.path().join("keep").is_file());
    }
}
