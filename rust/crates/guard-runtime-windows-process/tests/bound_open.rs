#![cfg(windows)]

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use std::process::Command;

use guard_runtime_windows_process::{
    handle_file_id, handle_final_path, open_bound_regular_file, open_bound_replaceable_file,
    regular_file_id,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("guard-bound-open-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let spelling = canonical.to_str().unwrap();
        Self(PathBuf::from(
            spelling.strip_prefix(r"\\?\").unwrap_or(spelling),
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bound_open_reads_the_inspected_file() {
    let fixture = Fixture::new("read");
    let path = fixture.0.join("source.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    let (expected, links) = regular_file_id(&path, false).unwrap();
    assert_eq!(links, 1);
    let mut file = open_bound_regular_file(&path).unwrap();
    assert_eq!(handle_file_id(&file).unwrap(), expected);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"fn main() {}\n");
}

#[test]
fn bound_open_rejects_a_junction_ancestor() {
    let fixture = Fixture::new("junction");
    let real = fixture.0.join("real");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("source.rs"), b"fn main() {}\n").unwrap();
    let junction = fixture.0.join("junction");
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .status()
        .unwrap();
    assert!(status.success());
    let error = open_bound_regular_file(&junction.join("source.rs")).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}

/// A handle opened through a junction reports the directory the junction
/// points at, which is what a scope check must compare, not the path that
/// was opened.
#[test]
fn a_handle_reports_where_it_points_not_how_it_was_opened() {
    let fixture = Fixture::new("final-path");
    let real = fixture.0.join("real");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("source.rs"), b"fn main() {}\n").unwrap();
    let junction = fixture.0.join("junction");
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .status()
        .unwrap();
    assert!(status.success());
    let opened = fs::File::open(junction.join("source.rs")).unwrap();
    let canonical_real = fs::canonicalize(&real).unwrap();
    let final_path = handle_final_path(&opened).unwrap();
    assert_eq!(final_path, canonical_real.join("source.rs"));
    assert!(!final_path.starts_with(fs::canonicalize(&fixture.0).unwrap().join("junction")));
}

#[test]
fn bound_open_rejects_a_symlink_leaf_and_follows_it_only_on_request() {
    let fixture = Fixture::new("symlink");
    let target = fixture.0.join("target.rs");
    fs::write(&target, b"fn target() {}\n").unwrap();
    let link = fixture.0.join("link.rs");
    std::os::windows::fs::symlink_file(&target, &link)
        .expect("Windows regression runner must support file symlinks");
    let error = open_bound_regular_file(&link).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(regular_file_id(&link, false).is_err());
    assert_eq!(
        regular_file_id(&link, true).unwrap(),
        regular_file_id(&target, false).unwrap()
    );
}

#[test]
fn bound_open_excludes_writers_while_the_handle_is_open() {
    let fixture = Fixture::new("writers");
    let path = fixture.0.join("source.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    let held = open_bound_regular_file(&path).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    drop(held);
    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert!(open_bound_regular_file(&path).is_err());
    drop(writer);
}

#[test]
fn file_ids_distinguish_a_replacement_with_the_same_contents() {
    let fixture = Fixture::new("replacement");
    let path = fixture.0.join("source.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    let (original, _) = regular_file_id(&path, false).unwrap();
    let replacement = fixture.0.join("replacement.rs");
    fs::write(&replacement, b"fn main() {}\n").unwrap();
    fs::rename(&replacement, &path).unwrap();
    let file = open_bound_regular_file(&path).unwrap();
    assert_ne!(handle_file_id(&file).unwrap(), original);
}

#[test]
fn replaceable_open_lets_a_rename_replace_the_file_and_keeps_its_bytes() {
    let fixture = Fixture::new("replaceable");
    let path = fixture.0.join("state.json");
    fs::write(&path, b"old").unwrap();
    let mut held = open_bound_replaceable_file(&path).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    let replacement = fixture.0.join("state.json.tmp");
    fs::write(&replacement, b"new").unwrap();
    fs::rename(&replacement, &path).unwrap();
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old");
    assert_eq!(fs::read(&path).unwrap(), b"new");
}
