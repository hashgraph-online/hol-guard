//! The hook spellings the daemon used to normalize in Python, checked
//! against real directories: the `/None` sentinel a CLI harness still
//! sends, the shared temporary root that means "no workspace", and the
//! payload file only Guard's own writer could have put where it is.

use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::{normalized_exec_workdir, normalized_hook_workspace, trusted_payload_reference};
use crate::guard_paths::python_realpath_lax;

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn canonical(path: &Path) -> PathBuf {
    python_realpath_lax(path).expect("an existing absolute path resolves")
}

fn workspace(value: &str, home_dir: &str, temp_dir: &Path) -> Option<String> {
    normalized_hook_workspace(value, home_dir, temp_dir).expect("a usable spelling")
}

#[test]
fn blank_and_sentinel_spellings_name_no_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    for value in ["", "   ", "none", "None", "NULL"] {
        assert_eq!(workspace(value, &home_dir, &temp_dir), None, "{value}");
    }
}

#[test]
fn a_trailing_none_component_names_the_directory_holding_it() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    let spelled = format!("{home_dir}/project/None");
    assert_eq!(
        workspace(&spelled, &home_dir, &temp_dir),
        Some(format!("{home_dir}/project")),
    );
}

#[test]
fn a_root_level_none_keeps_the_root_rather_than_dropping_the_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    // Python's `dirname("/None")` is `/`, which the trust rules then refuse.
    // Reading it as "no workspace" would let the request through instead.
    assert_eq!(
        workspace("/None", &home_dir, &temp_dir),
        Some("/".to_owned())
    );
}

#[test]
fn a_home_relative_spelling_expands_and_normalizes() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    assert_eq!(
        workspace("~/project/../project/./src", &home_dir, &temp_dir),
        Some(format!("{home_dir}/project/src")),
    );
}

#[test]
fn the_shared_temporary_root_itself_names_no_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    assert_eq!(workspace(&text(&temp_dir), &home_dir, &temp_dir), None);
}

#[test]
fn a_scratch_directory_under_the_temporary_root_is_kept() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    let scratch = TempDir::new().expect("a scratch directory");
    assert_eq!(
        workspace(&text(scratch.path()), &home_dir, &temp_dir),
        Some(text(scratch.path())),
    );
}

#[test]
fn an_exec_workdir_keeps_a_trailing_none_component() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    // `workdir` carries no sentinel: a directory really called `None` is
    // the directory the call asked for.
    let spelled = format!("{home_dir}/project/None");
    assert_eq!(
        normalized_exec_workdir(&spelled, &home_dir, &temp_dir).expect("a usable spelling"),
        Some(spelled),
    );
}

#[test]
fn an_exec_workdir_reads_its_sentinels_and_its_temporary_root() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    for value in ["", "  ", "none", "NULL", &text(&temp_dir)] {
        assert_eq!(
            normalized_exec_workdir(value, &home_dir, &temp_dir).expect("a usable spelling"),
            None,
            "{value}",
        );
    }
}

#[test]
fn a_payload_file_guard_wrote_is_the_one_reference_that_is_read() {
    let temp_dir = std::env::temp_dir();
    let holder = TempDir::new_in(&temp_dir).expect("a temporary holder");
    let directory = holder.path().join("hol-guard-hook-payload-abc123");
    std::fs::create_dir(&directory).expect("a payload directory");
    let payload = directory.join("payload.json");
    std::fs::write(&payload, b"{}").expect("a payload file");

    // The reference has to sit one level under a temporary root, in a
    // directory the payload writer named, so the holder is that root here.
    assert_eq!(
        trusted_payload_reference(&text(&payload), holder.path()),
        Some(canonical(&payload)),
    );
}

#[test]
fn a_reference_outside_a_payload_directory_is_refused() {
    let temp_dir = std::env::temp_dir();
    let holder = TempDir::new_in(&temp_dir).expect("a temporary holder");
    let directory = holder.path().join("someone-elses-directory");
    std::fs::create_dir(&directory).expect("a directory");
    let payload = directory.join("payload.json");
    std::fs::write(&payload, b"{}").expect("a file");
    assert_eq!(
        trusted_payload_reference(&text(&payload), holder.path()),
        None
    );
}

#[test]
fn a_reference_that_is_not_a_file_is_refused() {
    let temp_dir = std::env::temp_dir();
    let holder = TempDir::new_in(&temp_dir).expect("a temporary holder");
    let directory = holder.path().join("hol-guard-hook-payload-abc123");
    std::fs::create_dir(&directory).expect("a payload directory");
    assert_eq!(
        trusted_payload_reference(&text(&directory), holder.path()),
        None
    );
}

#[test]
fn a_relative_reference_is_refused_rather_than_resolved_here() {
    let temp_dir = std::env::temp_dir();
    let holder = TempDir::new_in(&temp_dir).expect("a temporary holder");
    assert_eq!(
        trusted_payload_reference("hol-guard-hook-payload-abc123/payload.json", holder.path()),
        None,
    );
}

#[test]
fn a_reference_outside_every_temporary_root_is_refused() {
    let home = TempDir::new().expect("a temporary home");
    let directory = home.path().join("hol-guard-hook-payload-abc123");
    std::fs::create_dir(&directory).expect("a payload directory");
    let payload = directory.join("payload.json");
    std::fs::write(&payload, b"{}").expect("a payload file");
    assert_eq!(
        trusted_payload_reference(&text(&payload), &std::env::temp_dir()),
        None,
    );
}

#[test]
fn the_fixed_temporary_roots_name_no_workspace_whatever_the_caller_uses() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    // A caller whose own temporary directory is somewhere else still skips
    // the roots Python listed after `tempfile.gettempdir()`.
    let elsewhere = TempDir::new().expect("a scratch temporary directory");
    for value in ["/tmp", "/var/tmp", "/tmp/x/..", " /tmp/ "] {
        assert_eq!(
            workspace(value, &home_dir, elsewhere.path()),
            None,
            "{value}"
        );
    }
}

#[test]
fn a_link_to_a_temporary_root_names_no_workspace_while_its_children_are_kept() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    let scratch = TempDir::new().expect("a scratch directory");
    let root = text(scratch.path());
    std::fs::create_dir(scratch.path().join("sub")).expect("a child directory");
    std::os::unix::fs::symlink("/tmp", scratch.path().join("to-tmp")).expect("a link to /tmp");
    std::os::unix::fs::symlink("../..", scratch.path().join("sub/up"))
        .expect("a link back out of the scratch directory");

    for link in ["to-tmp", "sub/up"] {
        let spelled = format!("{root}/{link}");
        assert_eq!(workspace(&spelled, &home_dir, &temp_dir), None, "{link}");
    }
    // A directory that merely sits under a temporary root, or has yet to be
    // created, is the workspace the hook named.
    for kept in [
        root.clone(),
        format!("{root}/sub"),
        format!("{root}/missing"),
        "/work/repo".to_owned(),
    ] {
        assert_eq!(
            workspace(&kept, &home_dir, &temp_dir),
            Some(kept.clone()),
            "{kept}",
        );
    }
}

#[test]
#[cfg(target_os = "macos")]
fn the_darwin_temporary_roots_name_no_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    assert_eq!(workspace("/private/tmp", &home_dir, &temp_dir), None);
    assert_eq!(workspace("/private/var/tmp", &home_dir, &temp_dir), None);
    // A per-user temporary directory that does not exist cannot be resolved,
    // and Python reads that as "no root", keeping the spelling.
    assert_eq!(
        workspace("/var/folders/abc/id/T", &home_dir, &temp_dir),
        Some("/var/folders/abc/id/T".to_owned()),
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn the_darwin_only_roots_are_ordinary_directories_elsewhere() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    assert_eq!(
        workspace("/private/tmp", &home_dir, &temp_dir),
        Some("/private/tmp".to_owned()),
    );
}

#[test]
fn an_exec_workdir_in_a_temporary_root_is_refused_rather_than_falling_through() {
    let home = TempDir::new().expect("a temporary home");
    let home_dir = text(home.path());
    let temp_dir = std::env::temp_dir();
    // The daemon reports `invalid_action_workdir` for this, instead of
    // reading the payload's `cwd` as the workspace.
    assert_eq!(
        normalized_exec_workdir("/tmp", &home_dir, &temp_dir).expect("a usable spelling"),
        None,
    );
    assert_eq!(
        normalized_exec_workdir("/tmp/None", &home_dir, &temp_dir).expect("a usable spelling"),
        Some("/tmp/None".to_owned()),
    );
}
