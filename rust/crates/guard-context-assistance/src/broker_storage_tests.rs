use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "guard-cigar-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn private_storage_rejects_links_permissions_unknown_files_size_and_identity_changes() {
    let fixture = Fixture::new();
    let root = &fixture.0;
    let handle = BrokerStorage::inspect(root).unwrap();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(handle.revalidate().is_err());
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = root.join("broker.sqlite3");
    std::fs::write(&db, b"synthetic database bytes").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(handle.revalidate().is_err());
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sealed = BrokerStorage::inspect(root).unwrap();
    std::fs::hard_link(&db, root.join("other")).unwrap();
    assert!(sealed.revalidate().is_err());
    std::fs::remove_file(root.join("other")).unwrap();
    std::fs::rename(&db, root.join("old")).unwrap();
    std::fs::write(&db, b"replacement").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(sealed.revalidate().is_err());
    std::fs::remove_file(root.join("old")).unwrap();
    assert!(
        sealed.revalidate().is_err(),
        "replacing the database must invalidate the pinned file even after the old name is removed"
    );
    let opened = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
    opened.set_len(DATABASE_BYTES + 1).unwrap();
    assert!(BrokerStorage::inspect(root).is_err());
    drop(opened);
    std::fs::remove_file(&db).unwrap();
    std::os::unix::fs::symlink("outside", &db).unwrap();
    assert!(BrokerStorage::inspect(root).is_err());
    std::fs::remove_file(&db).unwrap();
    let child = root.join("store");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    let pinned = BrokerStorage::inspect(&child).unwrap();
    std::fs::rename(&child, root.join("prior-store")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    assert!(pinned.revalidate().is_err());
}
