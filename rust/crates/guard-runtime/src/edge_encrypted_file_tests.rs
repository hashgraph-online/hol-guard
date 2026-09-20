use super::super::tests::Fixture;
use super::*;
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::time::Duration;

#[test]
fn actual_private_regular_file_is_read_without_mutation() {
    let fixture = Fixture::new(b"private ciphertext");
    let before = fs::metadata(&fixture.path).unwrap();
    assert_eq!(
        read(&fixture.path, 100, None).unwrap(),
        b"private ciphertext"
    );
    assert_eq!(
        file_identity(&before),
        file_identity(&fs::metadata(&fixture.path).unwrap())
    );
}

#[test]
fn file_and_directory_permissions_are_checked_on_owned_handles() {
    for directory in [false, true] {
        let fixture = Fixture::new(b"private ciphertext");
        let target = if directory {
            &fixture.root
        } else {
            &fixture.path
        };
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(if directory { 0o755 } else { 0o644 }),
        )
        .unwrap();
        assert_eq!(
            read(&fixture.path, 100, None).unwrap_err(),
            error("not_private")
        );
    }
}

#[test]
fn symlink_file_and_parent_are_refused_without_following() {
    let fixture = Fixture::new(b"private ciphertext");
    let link = fixture.root.join("link.json");
    symlink(&fixture.path, &link).unwrap();
    assert_eq!(read(&link, 100, None).unwrap_err(), error("read_failed"));
    let alias = fixture.root.with_extension("alias");
    symlink(&fixture.root, &alias).unwrap();
    let result = read(&alias.join("payload.json"), 100, None);
    fs::remove_file(alias).unwrap();
    assert_eq!(result.unwrap_err(), error("read_failed"));
}

#[test]
fn multiply_linked_file_and_non_regular_objects_are_refused() {
    let fixture = Fixture::new(b"private ciphertext");
    let other = fixture.root.join("second.json");
    fs::hard_link(&fixture.path, &other).unwrap();
    assert_eq!(
        read(&fixture.path, 100, None).unwrap_err(),
        error("not_private")
    );
    fs::remove_file(other).unwrap();
    fs::remove_file(&fixture.path).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.path)
        .unwrap();
    assert_eq!(
        read(&fixture.path, 100, None).unwrap_err(),
        error("not_private")
    );
}

#[test]
fn fifo_is_opened_nonblocking_then_refused() {
    let fixture = Fixture::new(b"private ciphertext");
    fs::remove_file(&fixture.path).unwrap();
    nix::unistd::mkfifo(&fixture.path, Mode::from_bits_truncate(0o600)).unwrap();
    assert_eq!(
        read(
            &fixture.path,
            100,
            Some(Instant::now() + Duration::from_secs(1))
        )
        .unwrap_err(),
        error("not_private")
    );
}

#[test]
fn relative_traversal_unowned_prefix_and_nested_directory_are_refused() {
    let fixture = Fixture::new(b"private ciphertext");
    let nested = fixture.root.join("hol-guard-hook-payload-nested");
    fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();
    for path in [
        PathBuf::from("payload.json"),
        fixture.root.join("../payload.json"),
        fixture
            .root
            .parent()
            .unwrap()
            .join("not-guard-owned/payload.json"),
        nested.join("payload.json"),
    ] {
        assert_eq!(read(&path, 100, None).unwrap_err(), error("path_invalid"));
    }
}

#[test]
fn size_limit_is_enforced_before_and_during_bounded_read() {
    let fixture = Fixture::new(b"abcdef");
    assert_eq!(
        read(&fixture.path, 5, None).unwrap_err(),
        error("size_invalid")
    );
    let result = read_checked(&fixture.path, 6, None, || {
        fs::write(&fixture.path, b"abcdefg").unwrap();
    });
    assert_eq!(result.unwrap_err(), error("size_invalid"));
}

#[test]
fn file_replacement_after_open_is_refused() {
    let fixture = Fixture::new(b"abcdef");
    let result = read_checked(&fixture.path, 100, None, || {
        fs::rename(&fixture.path, fixture.root.join("old.json")).unwrap();
        fs::write(&fixture.path, b"abcdef").unwrap();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    });
    assert_eq!(result.unwrap_err(), error("path_changed"));
}

#[test]
fn private_parent_replacement_after_open_is_refused() {
    let fixture = Fixture::new(b"abcdef");
    let moved = fixture.root.with_extension("moved");
    let result = read_checked(&fixture.path, 100, None, || {
        fs::rename(&fixture.root, &moved).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.root)
            .unwrap();
    });
    fs::remove_dir(&fixture.root).unwrap();
    fs::rename(moved, &fixture.root).unwrap();
    assert_eq!(result.unwrap_err(), error("path_changed"));
}

#[test]
fn same_descriptor_growth_and_permission_changes_are_refused() {
    for directory in [false, true] {
        let fixture = Fixture::new(b"abcdef");
        let result = read_checked(&fixture.path, 100, None, || {
            let target = if directory {
                &fixture.root
            } else {
                &fixture.path
            };
            fs::set_permissions(target, fs::Permissions::from_mode(0o755)).unwrap();
        });
        assert_eq!(result.unwrap_err(), error("path_changed"));
    }
    let fixture = Fixture::new(b"abcdef");
    let result = read_checked(&fixture.path, 100, None, || {
        fs::write(&fixture.path, b"abcdefg").unwrap();
    });
    assert_eq!(result.unwrap_err(), error("path_changed"));
}

#[test]
fn original_deadline_is_not_restarted_after_open() {
    let fixture = Fixture::new(b"abcdef");
    // Give actual hosted filesystem admission a bounded window before consuming
    // that same Instant in the after-open barrier; no production budget changes.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut opened = false;
    let result = read_checked(&fixture.path, 100, Some(deadline), || {
        opened = true;
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
    });
    assert!(opened);
    assert_eq!(result.unwrap_err(), "native_request_deadline_exceeded");
}

#[test]
fn arbitrary_lexical_alias_to_temporary_root_is_refused() {
    let fixture = Fixture::new(b"private ciphertext");
    let alias_owner = Fixture::new(b"alias owner");
    let alias = alias_owner.root.join("temporary-alias");
    symlink(fixture.root.parent().unwrap(), &alias).unwrap();
    let alternate = alias
        .join(fixture.root.file_name().unwrap())
        .join("payload.json");
    // The same actual bytes are reachable, but this is not a generated temp-root path.
    assert_eq!(fs::read(&alternate).unwrap(), b"private ciphertext");
    assert_eq!(
        read(&alternate, 100, None).unwrap_err(),
        error("path_invalid")
    );
    assert_eq!(
        read(&fixture.path, 100, None).unwrap(),
        b"private ciphertext"
    );
}
