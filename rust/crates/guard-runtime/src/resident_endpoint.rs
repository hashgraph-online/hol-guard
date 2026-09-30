//! Native Unix listener ownership, independent of a reusable endpoint name.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixEndpointIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) owner: u32,
}

#[cfg(unix)]
impl UnixEndpointIdentity {
    pub(crate) fn capture(path: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native_socket_identity_unavailable".to_owned())?;
        if !metadata.file_type().is_socket() {
            return Err("native_socket_identity_invalid".to_owned());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    fn remove_if_same(&self, path: &std::path::Path) -> bool {
        if Self::capture(path).as_ref() != Ok(self) {
            return false;
        }
        std::fs::remove_file(path).is_ok()
    }
}

#[cfg(unix)]
pub(crate) struct OwnedUnixEndpoint<'a> {
    // Native replacement acquires the same home owner lock. Keep it held
    // across identity verification and unlink during endpoint teardown.
    _owner_lock: &'a crate::managed_resident::ManagedOwnerLock,
    path: std::path::PathBuf,
    pub(crate) identity: UnixEndpointIdentity,
}

#[cfg(unix)]
impl<'a> OwnedUnixEndpoint<'a> {
    pub(crate) fn capture(
        path: &std::path::Path,
        owner_lock: &'a crate::managed_resident::ManagedOwnerLock,
    ) -> Result<Self, String> {
        Ok(Self {
            _owner_lock: owner_lock,
            path: path.to_owned(),
            identity: UnixEndpointIdentity::capture(path)?,
        })
    }
}

#[cfg(unix)]
impl Drop for OwnedUnixEndpoint<'_> {
    fn drop(&mut self) {
        let _ = self.identity.remove_if_same(&self.path);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::managed_resident::acquire_managed_owner_lock;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("ep-{}", hex::encode(nonce)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn dropping_owned_endpoint_preserves_replacement_socket() {
        let directory = fixture();
        let path = directory.join("s");
        let original = UnixListener::bind(&path).unwrap();
        let owner_lock = acquire_managed_owner_lock(&directory).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path, &owner_lock).unwrap();
        fs::rename(&path, directory.join("original")).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        let identity = UnixEndpointIdentity::capture(&path).unwrap();
        drop(ownership);
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    assert!(matches!(acquire_managed_owner_lock(&directory),
                    Err(error) if error == "native_resident_owner_busy"));
                })
                .join()
                .unwrap();
        });
        assert_eq!(UnixEndpointIdentity::capture(&path).unwrap(), identity);
        drop(replacement);
        drop(original);
        drop(owner_lock);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dropping_owned_endpoint_removes_only_its_socket() {
        let directory = fixture();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let owner_lock = acquire_managed_owner_lock(&directory).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path, &owner_lock).unwrap();
        drop(listener);
        drop(ownership);
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    assert!(matches!(acquire_managed_owner_lock(&directory),
                    Err(error) if error == "native_resident_owner_busy"));
                })
                .join()
                .unwrap();
        });
        assert!(!path.exists());
        drop(owner_lock);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cleanup_does_not_follow_a_replacement_symlink() {
        let directory = fixture();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let owner_lock = acquire_managed_owner_lock(&directory).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path, &owner_lock).unwrap();
        fs::rename(&path, directory.join("original")).unwrap();
        std::os::unix::fs::symlink(directory.join("original"), &path).unwrap();
        drop(ownership);
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    assert!(matches!(acquire_managed_owner_lock(&directory),
                    Err(error) if error == "native_resident_owner_busy"));
                })
                .join()
                .unwrap();
        });
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(UnixEndpointIdentity::capture(&directory.join("original")).is_ok());
        drop(listener);
        drop(owner_lock);
        fs::remove_dir_all(directory).unwrap();
    }
}
