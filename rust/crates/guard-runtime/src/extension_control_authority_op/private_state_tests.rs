//! Pins the private-state writer to its file list and limits, and to the
//! private file the native readers open.

use super::private_state::{publish, FILES};

fn record(length: usize) -> Vec<u8> {
    format!(r#"{{"padding":"{}"}}"#, "a".repeat(length - 14)).into_bytes()
}

#[test]
fn a_name_outside_the_list_is_refused_before_anything_is_written() {
    let home = tempfile::tempdir().unwrap();
    for name in [
        "command-control-authority.v1.json",
        "../business-source-anchor.v1.json",
        "",
    ] {
        assert_eq!(
            publish(home.path(), name, b"{}"),
            Err("native_private_state_invalid".to_owned())
        );
    }
    assert!(!home.path().join("native-runtime").exists());
}

#[test]
fn an_empty_or_oversized_payload_is_refused() {
    let home = tempfile::tempdir().unwrap();
    for (name, maximum) in FILES {
        assert!(publish(home.path(), name, b"").is_err());
        let oversized = record(usize::try_from(maximum).unwrap() + 1);
        assert_eq!(
            publish(home.path(), name, &oversized),
            Err("native_private_state_invalid".to_owned())
        );
    }
}

#[cfg(unix)]
#[test]
fn each_listed_file_lands_private_at_its_full_limit() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, maximum) in FILES {
        let first = record(64);
        let full = record(usize::try_from(maximum).unwrap());
        publish(home.path(), name, &first).unwrap();
        publish(home.path(), name, &full).unwrap();
        let path = home.path().join("native-runtime").join(name);
        assert_eq!(std::fs::read(&path).unwrap(), full);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
    let entries = std::fs::read_dir(home.path().join("native-runtime"))
        .unwrap()
        .count();
    assert_eq!(entries, FILES.len(), "no temporary file is left behind");
}
