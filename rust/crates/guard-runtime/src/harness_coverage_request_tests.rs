use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{read_request, write_request, MAX_REQUEST_BYTES, REQUEST_NAME};
use crate::harness_coverage::ErrorClass;

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
}

impl Fixture {
    fn guard_home(&self) -> PathBuf {
        self.home.join(".hol-guard")
    }

    fn request(&self) -> PathBuf {
        self.guard_home().join(REQUEST_NAME)
    }
}

fn setup() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(root.path()).unwrap().join("home");
    fs::create_dir_all(home.join(".hol-guard")).unwrap();
    set_mode(&home.join(".hol-guard"), 0o700);
    Fixture { _root: root, home }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn refusal(result: Result<Vec<Value>, super::CoverageError>) -> (ErrorClass, &'static str) {
    let error = result.unwrap_err();
    (error.class, error.reason_code)
}

fn installs() -> Vec<Value> {
    vec![json!({"active": true, "harness": "codex", "manifest": {"note": "caf\u{e9}"}})]
}

#[test]
fn the_request_is_written_as_python_wrote_it() {
    let fixture = setup();
    write_request(&fixture.home, &installs()).unwrap();
    let written = fs::read(fixture.request()).unwrap();
    let expected = concat!(
        r#"{"installs":[{"active":true,"harness":"codex","manifest":{"note":"café"}}],"#,
        r#""schemaVersion":"hol-guard-harness-coverage-request.v1"}"#,
        "\n"
    );
    assert_eq!(String::from_utf8(written).unwrap(), expected);
}

#[test]
fn a_request_too_large_to_hold_is_never_written() {
    let fixture = setup();
    let filler = "x".repeat(MAX_REQUEST_BYTES as usize);
    let result = write_request(&fixture.home, &[json!({"harness": filler})]);
    let error = result.unwrap_err();
    assert_eq!(
        (error.class, error.reason_code),
        (
            ErrorClass::Value,
            "harness_coverage_request_capacity_exceeded"
        )
    );
    assert!(fs::symlink_metadata(fixture.request()).is_err());
}

#[test]
fn a_missing_request_or_guard_home_is_absent() {
    let fixture = setup();
    let absent = (ErrorClass::Value, "harness_coverage_request_absent");
    assert_eq!(refusal(read_request(&fixture.home)), absent);
    fs::remove_dir(fixture.guard_home()).unwrap();
    assert_eq!(refusal(read_request(&fixture.home)), absent);
}

#[cfg(unix)]
#[test]
fn a_private_request_reads_back_its_installs() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = setup();
    write_request(&fixture.home, &installs()).unwrap();
    let mode = fs::metadata(fixture.request())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(read_request(&fixture.home).unwrap(), installs());
}

#[cfg(unix)]
#[test]
fn a_request_others_could_change_is_refused() {
    let acl_invalid = (
        ErrorClass::Permission,
        "harness_coverage_request_acl_invalid",
    );

    let fixture = setup();
    write_request(&fixture.home, &installs()).unwrap();
    set_mode(&fixture.request(), 0o640);
    assert_eq!(refusal(read_request(&fixture.home)), acl_invalid);

    let fixture = setup();
    write_request(&fixture.home, &installs()).unwrap();
    set_mode(&fixture.guard_home(), 0o720);
    assert_eq!(refusal(read_request(&fixture.home)), acl_invalid);
}

#[cfg(unix)]
#[test]
fn a_linked_request_is_refused() {
    let fixture = setup();
    let elsewhere = fixture.home.join("elsewhere.json");
    fs::write(&elsewhere, b"{}").unwrap();
    set_mode(&elsewhere, 0o600);
    std::os::unix::fs::symlink(&elsewhere, fixture.request()).unwrap();
    assert_eq!(
        refusal(read_request(&fixture.home)),
        (
            ErrorClass::Permission,
            "harness_coverage_request_acl_invalid"
        )
    );
}

#[cfg(unix)]
#[test]
fn a_request_without_the_exact_shape_is_invalid() {
    let invalid = (ErrorClass::Value, "harness_coverage_request_invalid");
    let bodies = [
        "not json".to_owned(),
        "[]".to_owned(),
        json!({"schemaVersion": super::SCHEMA_VERSION}).to_string(),
        json!({"schemaVersion": "other.v1", "installs": []}).to_string(),
        json!({"schemaVersion": super::SCHEMA_VERSION, "installs": {}}).to_string(),
        json!({"schemaVersion": super::SCHEMA_VERSION, "installs": [1]}).to_string(),
        json!({"schemaVersion": super::SCHEMA_VERSION, "installs": [], "extra": 1}).to_string(),
    ];
    for body in bodies {
        let fixture = setup();
        fs::write(fixture.request(), body.as_bytes()).unwrap();
        set_mode(&fixture.request(), 0o600);
        assert_eq!(refusal(read_request(&fixture.home)), invalid, "{body}");
    }
}

#[cfg(unix)]
#[test]
fn a_registered_request_counts_its_harnesses() {
    use std::os::unix::fs::MetadataExt;

    use crate::harness_coverage::{register_requested, verify};

    let fixture = setup();
    let config = fixture.home.join("config.toml");
    fs::write(&config, b"managed").unwrap();
    let install = json!({"active": true, "harness": "codex", "manifest": {"config_path": config}});
    write_request(&fixture.home, &[install]).unwrap();
    let state_root = fixture.home.join("state");
    let owner = fs::metadata(&fixture.home).unwrap().uid();
    register_requested(&state_root, owner, &fixture.home).unwrap();
    let coverage = verify(&state_root, owner, &["codex".to_owned()])
        .coverage
        .unwrap();
    assert_eq!((coverage.required, coverage.protected), (1, 1));
}

#[cfg(not(unix))]
#[test]
fn a_request_is_never_trusted_without_owner_and_mode_bits() {
    let fixture = setup();
    write_request(&fixture.home, &installs()).unwrap();
    assert_eq!(
        refusal(read_request(&fixture.home)),
        (
            ErrorClass::Permission,
            "harness_coverage_request_acl_invalid"
        )
    );
}
