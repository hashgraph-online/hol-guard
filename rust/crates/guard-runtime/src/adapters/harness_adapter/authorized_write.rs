//! `write_text_at_authorized_path`: an owner-only atomic write beneath a
//! parent the caller resolved. On Unix every directory on the way is opened
//! without following a link, and the file is created and renamed relative to
//! the held handle, so a parent swapped for a link after resolution cannot
//! redirect the write.

use std::path::Path;

#[cfg(unix)]
pub(super) fn write_beneath_parent(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::path::Component;

    use nix::fcntl::{open, openat, renameat, OFlag};
    use nix::sys::stat::{fchmod, Mode};
    use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

    let refused = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Guard refused to write {}", path.display()),
        )
    };
    let name = path.file_name().ok_or_else(refused)?;
    let mut components = path.parent().ok_or_else(refused)?.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refused());
    }
    let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW;
    let mut directory = open("/", flags, Mode::empty())?;
    for component in components {
        let Component::Normal(part) = component else {
            return Err(refused());
        };
        directory = openat(&directory, part, flags, Mode::empty())?;
    }
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(std::io::Error::other)?;
    let temporary = format!(".{}.{}", name.to_string_lossy(), hex::encode(token));
    let private = Mode::S_IRUSR | Mode::S_IWUSR;
    let create =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let written = openat(&directory, temporary.as_str(), create, private)
        .map_err(std::io::Error::from)
        .and_then(|descriptor| {
            let mut file = std::fs::File::from(descriptor);
            fchmod(&file, private)?;
            file.write_all(bytes)?;
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

#[cfg(not(unix))]
pub(super) fn write_beneath_parent(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    for ancestor in path.ancestors().skip(1) {
        let linked = std::fs::symlink_metadata(ancestor)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if linked {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Guard refused to write through a link at {}",
                    ancestor.display()
                ),
            ));
        }
    }
    crate::encrypted_secret_store::atomic_write_bytes(path, bytes, 0o600)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::write_beneath_parent;

    #[test]
    fn a_linked_parent_does_not_redirect_the_write() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (real, outside) = (root.join("real"), root.join("outside"));
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        write_beneath_parent(&real.join("config.json"), b"{}\n").unwrap();
        let mode = std::fs::metadata(real.join("config.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&outside, &real).unwrap();
        assert!(write_beneath_parent(&real.join("config.json"), b"{}\n").is_err());
        assert!(!outside.join("config.json").exists());
    }
}
