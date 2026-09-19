use super::*;
use std::process::Command;
use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::SetSecurityInfo;
use windows_permissions::{LocalBox, SecurityDescriptor};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-windows-source-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("src")).unwrap();
        fs::write(path.join("src/source.rs"), b"fn source() {}\n").unwrap();
        Self(path)
    }

    fn source(&self) -> PathBuf {
        self.0.join("src/source.rs")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn source_read_preserves_inherited_permissions_and_real_identity() {
    let fixture = Fixture::new("identity");
    let mut file = SourceFile::open(&fixture.source()).unwrap();
    let before = file.identity().unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"fn source() {}\n");
    assert_eq!(before.links, 1);
    assert_eq!(before.size, bytes.len() as u64);
    assert!(before == file.identity().unwrap());
    file.validate_path().unwrap();
}

#[test]
fn held_source_blocks_parent_and_leaf_replacement_and_writers() {
    let fixture = Fixture::new("barriers");
    let file = SourceFile::open(&fixture.source()).unwrap();
    assert!(fs::rename(fixture.0.join("src"), fixture.0.join("moved")).is_err());
    assert!(fs::rename(fixture.source(), fixture.0.join("replacement.rs")).is_err());
    assert!(fs::remove_file(fixture.source()).is_err());
    assert!(OpenOptions::new()
        .write(true)
        .open(fixture.source())
        .is_err());
    file.validate_path().unwrap();
    drop(file);
    OpenOptions::new()
        .write(true)
        .open(fixture.source())
        .unwrap();
    fs::rename(fixture.0.join("src"), fixture.0.join("moved")).unwrap();
}

#[test]
fn source_open_rejects_an_existing_writer() {
    let fixture = Fixture::new("writer");
    let writer = OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(fixture.source())
        .unwrap();
    assert!(SourceFile::open(&fixture.source()).is_err());
    drop(writer);
    SourceFile::open(&fixture.source()).unwrap();
}

#[test]
fn original_parent_junction_is_rejected_before_canonicalization() {
    let fixture = Fixture::new("junction");
    let junction = fixture.0.join("alias");
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(fixture.0.join("src"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(SourceFile::open(&junction.join("source.rs")).is_err());
    fs::remove_dir(junction).unwrap();
}

#[test]
fn original_leaf_symlink_is_rejected() {
    let fixture = Fixture::new("symlink");
    let alias = fixture.0.join("alias.rs");
    std::os::windows::fs::symlink_file(fixture.source(), &alias).unwrap();
    assert!(SourceFile::open(&alias).is_err());
    fs::remove_file(alias).unwrap();
}

#[test]
fn source_paths_reject_devices_streams_and_parent_components() {
    for path in [
        r"\\server\share\source.rs",
        r"\\.\pipe\source.rs",
        r"C:\src\source.rs:other",
        r"C:\src\..\source.rs",
        r"C:\src\NUL.rs",
        r"C:\src\COM1.txt",
        r"C:\src\source.rs.",
        r"C:\src\source.rs ",
    ] {
        assert!(checked_absolute_path(Path::new(path)).is_err(), "{path}");
    }
}

#[test]
fn source_read_obeys_denied_read_acl_without_repairing_it() {
    let fixture = Fixture::new("denied-read");
    let mut handle = security_handle(&fixture.source());
    let original = GetSecurityInfo(
        &handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
    )
    .unwrap();
    let owner = current_process_sid().unwrap().to_string();
    let denied: LocalBox<SecurityDescriptor> =
        format!("D:P(D;;FR;;;{owner})(A;;FA;;;{owner})(A;;FA;;;SY)")
            .parse()
            .unwrap();
    set_dacl(&mut handle, &denied);
    // Compare copies of the stored descriptor on both sides of the read, not
    // the requested SDDL with the result of applying it to a filesystem object.
    let before = GetSecurityInfo(
        &handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Group | SecurityInformation::Dacl,
    )
    .unwrap();
    let ordinary_read = File::open(fixture.source());
    let result = SourceFile::open(&fixture.source());
    let after = GetSecurityInfo(
        &handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Group | SecurityInformation::Dacl,
    )
    .unwrap();
    let unchanged =
        before.as_sddl().unwrap().to_string_lossy() == after.as_sddl().unwrap().to_string_lossy();
    set_dacl(&mut handle, &original);
    assert!(matches!(ordinary_read, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(unchanged);
}

#[test]
fn held_identity_detects_a_security_descriptor_change() {
    let fixture = Fixture::new("security-change");
    let mut handle = security_handle(&fixture.source());
    let original = GetSecurityInfo(
        &handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
    )
    .unwrap();
    let file = SourceFile::open(&fixture.source()).unwrap();
    let before = file.identity().unwrap();
    let owner = current_process_sid().unwrap().to_string();
    let read_only: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FR;;;{owner})(A;;FA;;;SY)").parse().unwrap();
    set_dacl(&mut handle, &read_only);
    let after = file.identity().unwrap();
    set_dacl(&mut handle, &original);
    assert!(before != after);
}

fn security_handle(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .unwrap()
}

fn set_dacl(handle: &mut File, descriptor: &SecurityDescriptor) {
    SetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .unwrap();
}

#[path = "source_drive_alias_tests.rs"]
mod drive_alias_tests;
