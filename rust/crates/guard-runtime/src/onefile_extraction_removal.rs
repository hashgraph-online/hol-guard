//! Deletes one extraction directory with the entries a sweep recognises it
//! by removed last: everything else first, then the Guard package directory,
//! then the owner marker. A sweep killed part way through therefore leaves a
//! directory that still carries its marker or package directory, which the
//! next sweep reclaims.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::Path;

/// Opens `path` itself, never what a link or junction at `path` names, so
/// a candidate replaced after the sweep checked it is refused instead of
/// walked.
#[cfg(unix)]
fn open_root(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Windows has no descriptor-relative removal, so the root stays open
/// without delete sharing for the whole walk: nothing can rename or replace
/// it until its entries are gone.
#[cfg(windows)]
fn open_root(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let root = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = root.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extraction directory is not a plain directory",
        ));
    }
    Ok(root)
}

pub(crate) fn remove_extraction_dir(
    path: &Path,
    marker_name: &str,
    package_name: &str,
) -> io::Result<()> {
    let root = open_root(path)?;
    for name in removal_order(entry_names(&root, path)?, marker_name, package_name) {
        remove_entry(&root, path, &name, 0)?;
    }
    drop(root);
    // Removing a link or junction that replaced the root removes only it.
    fs::remove_dir(path)
}

/// The directory's entries in deletion order.
fn removal_order(mut names: Vec<OsString>, marker_name: &str, package_name: &str) -> Vec<OsString> {
    let rank = |name: &OsString| match name.to_str() {
        Some(name) if name == marker_name => 2,
        Some(name) if name == package_name => 1,
        _ => 0,
    };
    names.sort_by_key(rank);
    names
}

#[cfg(unix)]
mod walk {
    //! Every step is relative to an opened directory, and no step follows a
    //! link, so a directory swapped for a link mid-sweep is never entered.

    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use nix::errno::Errno;
    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;
    use nix::unistd::{unlinkat, UnlinkatFlags};

    /// Deeper trees are refused rather than walked; an extraction is shallow.
    const MAX_DEPTH: usize = 64;

    fn directory_flags() -> OFlag {
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC
    }

    pub(super) fn entry_names(directory: &File, _path: &Path) -> io::Result<Vec<OsString>> {
        let fd = openat(directory, ".", directory_flags(), Mode::empty())?;
        let mut listing = nix::dir::Dir::from_fd(fd)?;
        let mut names = Vec::new();
        for entry in listing.iter() {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name != "." && name != ".." {
                names.push(name.to_os_string());
            }
        }
        Ok(names)
    }

    pub(super) fn remove_entry(
        parent: &File,
        parent_path: &Path,
        name: &OsStr,
        depth: usize,
    ) -> io::Result<()> {
        match openat(parent, name, directory_flags(), Mode::empty()) {
            Ok(fd) => {
                if depth >= MAX_DEPTH {
                    return Err(io::Error::other("extraction directory is too deep"));
                }
                let child = File::from(fd);
                for entry in entry_names(&child, parent_path)? {
                    remove_entry(&child, parent_path, &entry, depth + 1)?;
                }
                drop(child);
                unlinkat(parent, name, UnlinkatFlags::RemoveDir)?;
                Ok(())
            }
            // A file or a link: unlink the entry itself.
            Err(Errno::ENOTDIR | Errno::ELOOP) => {
                unlinkat(parent, name, UnlinkatFlags::NoRemoveDir)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(windows)]
mod walk {
    //! The held root cannot be replaced, and the standard library removes a
    //! subtree through handles without following a link or junction.

    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File};
    use std::io;
    use std::path::Path;

    pub(super) fn entry_names(_directory: &File, path: &Path) -> io::Result<Vec<OsString>> {
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }

    pub(super) fn remove_entry(
        _parent: &File,
        parent_path: &Path,
        name: &OsStr,
        _depth: usize,
    ) -> io::Result<()> {
        let entry = parent_path.join(name);
        let kind = fs::symlink_metadata(&entry)?.file_type();
        if kind.is_dir() {
            return fs::remove_dir_all(&entry);
        }
        match fs::remove_file(&entry) {
            // A directory symlink is removed as a directory.
            Err(_) if kind.is_symlink() => fs::remove_dir(&entry),
            result => result,
        }
    }
}

use walk::{entry_names, remove_entry};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        let listed = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let order = removal_order(listed, MARKER, PACKAGE);
        let names: Vec<_> = order.iter().map(|name| name.to_str().unwrap()).collect();
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

    #[cfg(unix)]
    #[test]
    fn a_root_replaced_by_a_symlink_is_refused_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join(MARKER), b"{}").unwrap();
        fs::write(outside.path().join("keep"), b"k").unwrap();
        let candidate = root.path().join("_MEIswap");
        std::os::unix::fs::symlink(outside.path(), &candidate).unwrap();
        assert!(remove_extraction_dir(&candidate, MARKER, PACKAGE).is_err());
        assert!(outside.path().join("keep").is_file());
        assert!(outside.path().join(MARKER).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_nested_symlink_to_a_directory_is_unlinked_not_walked() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"k").unwrap();
        let directory = plant(root.path());
        std::os::unix::fs::symlink(
            outside.path(),
            directory.join(PACKAGE).join("guard").join("dir"),
        )
        .unwrap();
        remove_extraction_dir(&directory, MARKER, PACKAGE).unwrap();
        assert!(outside.path().join("keep").is_file());
        assert!(fs::symlink_metadata(&directory).is_err());
    }
}
