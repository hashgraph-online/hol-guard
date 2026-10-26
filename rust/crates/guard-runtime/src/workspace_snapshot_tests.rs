use std::fs;
use std::path::Path;

use serde_json::Value;

use super::*;

fn request(root: &Path, mode: SnapshotMode) -> SnapshotRequest {
    SnapshotRequest {
        root: root.to_str().unwrap().to_owned(),
        mode,
        max_entries: 0,
        max_total_bytes: 0,
        max_file_bytes: 0,
        max_visited_entries: 0,
        secrets: false,
        secret_key: None,
        skills: false,
        hooks: false,
        plugins: false,
    }
}

fn content(root: &Path) -> Value {
    snapshot(&request(root, SnapshotMode::Content)).unwrap()
}

fn digest(result: &Value) -> String {
    result["snapshot_digest"].as_str().unwrap().to_owned()
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("package.json"), "{\"name\":\"app\"}").unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/index.js"), "console.log(1)\n").unwrap();
    dir
}

#[test]
fn identical_content_yields_identical_digest_and_complete_coverage() {
    let dir = project();
    let first = content(dir.path());
    let second = content(dir.path());
    assert_eq!(digest(&first), digest(&second));
    assert_eq!(first["coverage"], "complete");
    assert_eq!(first["entry_count"], 2);
    assert_eq!(first["schema"], "guard.workspace-snapshot.v1");
}

#[test]
fn dirty_and_untracked_content_change_the_digest() {
    let dir = project();
    let clean = digest(&content(dir.path()));
    fs::write(dir.path().join("src/index.js"), "console.log(2)\n").unwrap();
    let dirty = digest(&content(dir.path()));
    assert_ne!(clean, dirty);
    fs::write(dir.path().join("untracked.py"), "print(1)\n").unwrap();
    assert_ne!(dirty, digest(&content(dir.path())));
}

#[test]
fn policy_directories_are_recorded_but_never_read() {
    let dir = project();
    fs::create_dir_all(dir.path().join("node_modules/left-pad")).unwrap();
    fs::write(dir.path().join("node_modules/left-pad/index.js"), "x").unwrap();
    let first = content(dir.path());
    assert_eq!(first["entry_count"], 2);
    assert_eq!(first["excluded"]["directories"], 1);
    fs::write(dir.path().join("node_modules/left-pad/index.js"), "y").unwrap();
    assert_eq!(digest(&first), digest(&content(dir.path())));
}

#[test]
fn sensitive_basenames_are_excluded_without_reading_content() {
    let dir = project();
    fs::write(dir.path().join(".env"), "TOKEN=one").unwrap();
    let first = content(dir.path());
    assert_eq!(first["excluded"]["sensitive"], 1);
    assert_eq!(first["entry_count"], 2);
    fs::write(dir.path().join(".env"), "TOKEN=two").unwrap();
    assert_eq!(digest(&first), digest(&content(dir.path())));
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed_but_a_retarget_changes_the_digest() {
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), "outside").unwrap();
    fs::write(outside.path().join("other.txt"), "outside-2").unwrap();
    fs::create_dir_all(outside.path().join("dir")).unwrap();
    fs::write(outside.path().join("dir/inner.txt"), "inner").unwrap();
    let dir = project();
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), dir.path().join("link")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("dir"), dir.path().join("linked-dir")).unwrap();
    let first = content(dir.path());
    assert_eq!(first["entry_count"], 2);
    assert_eq!(first["excluded"]["symlinks"], 2);
    assert_eq!(first["coverage"], "complete");
    fs::remove_file(dir.path().join("link")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("other.txt"), dir.path().join("link")).unwrap();
    assert_ne!(digest(&first), digest(&content(dir.path())));
}

#[test]
fn entry_cap_reports_partial_coverage() {
    let dir = project();
    for index in 0..5 {
        fs::write(dir.path().join(format!("f{index}.txt")), "x").unwrap();
    }
    let mut capped = request(dir.path(), SnapshotMode::Content);
    capped.max_entries = 3;
    let result = snapshot(&capped).unwrap();
    assert_eq!(result["entry_count"], 3);
    assert_eq!(result["coverage"], "partial");
    assert_eq!(result["partial_reasons"][0], "entry_cap");
}

#[test]
fn byte_budget_reports_partial_coverage() {
    let dir = project();
    fs::write(dir.path().join("big.txt"), vec![b'a'; 4096]).unwrap();
    let mut capped = request(dir.path(), SnapshotMode::Content);
    capped.max_total_bytes = 1024;
    let result = snapshot(&capped).unwrap();
    assert_eq!(result["coverage"], "partial");
    assert!(result["partial_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "byte_cap"));
}

#[test]
fn oversize_detector_input_is_partial_but_oversize_asset_is_only_excluded() {
    let dir = project();
    fs::write(dir.path().join("logo.bin"), vec![0_u8; 2048]).unwrap();
    let mut limited = request(dir.path(), SnapshotMode::Content);
    limited.max_file_bytes = 1024;
    let asset_only = snapshot(&limited).unwrap();
    assert_eq!(asset_only["coverage"], "complete");
    assert_eq!(asset_only["excluded"]["oversize"], 1);
    fs::write(dir.path().join("package-lock.json"), vec![b' '; 2048]).unwrap();
    let lockfile = snapshot(&limited).unwrap();
    assert_eq!(lockfile["coverage"], "partial");
    assert_eq!(lockfile["partial_reasons"][0], "oversize_detector_input");
}

#[test]
fn an_unsupported_lockfile_leaves_the_snapshot_partial() {
    let dir = project();
    let clean = snapshot(&request(dir.path(), SnapshotMode::Content)).unwrap();
    assert_eq!(clean["coverage"], "complete");
    fs::create_dir(dir.path().join("app")).unwrap();
    fs::write(dir.path().join("app").join("pubspec.lock"), "packages:\n").unwrap();
    for mode in [SnapshotMode::Content, SnapshotMode::Stat] {
        let result = snapshot(&request(dir.path(), mode)).unwrap();
        assert_eq!(result["coverage"], "partial");
        assert_eq!(
            result["partial_reasons"],
            serde_json::json!(["unsupported_dependency_input"])
        );
    }
}

#[test]
fn a_dependency_file_below_audit_discovery_leaves_the_snapshot_partial() {
    let dir = project();
    let reachable = dir.path().join("services").join("api").join("web");
    fs::create_dir_all(&reachable).unwrap();
    fs::write(reachable.join("package.json"), "{}").unwrap();
    let shallow = snapshot(&request(dir.path(), SnapshotMode::Content)).unwrap();
    assert_eq!(shallow["coverage"], "complete");
    let deep = reachable.join("client");
    fs::create_dir(&deep).unwrap();
    fs::write(deep.join("package-lock.json"), "{}").unwrap();
    fs::write(deep.join("notes.md"), "# notes").unwrap();
    for mode in [SnapshotMode::Content, SnapshotMode::Stat] {
        let result = snapshot(&request(dir.path(), mode)).unwrap();
        assert_eq!(result["coverage"], "partial");
        assert_eq!(
            result["partial_reasons"],
            serde_json::json!(["undiscovered_dependency_input"])
        );
    }
}

#[test]
fn stat_mode_reads_no_content_and_tracks_additions() {
    let dir = project();
    let first = snapshot(&request(dir.path(), SnapshotMode::Stat)).unwrap();
    assert_eq!(first["mode"], "stat");
    assert_eq!(first["hashed_bytes"], 0);
    fs::write(dir.path().join("new.rs"), "fn x() {}").unwrap();
    let second = snapshot(&request(dir.path(), SnapshotMode::Stat)).unwrap();
    assert_ne!(digest(&first), digest(&second));
    assert_ne!(digest(&first), digest(&content(dir.path())));
}

#[test]
fn relative_or_missing_roots_are_rejected() {
    let mut relative = request(Path::new("/"), SnapshotMode::Content);
    relative.root = "relative/path".to_owned();
    assert_eq!(
        snapshot(&relative).unwrap_err(),
        "workspace_snapshot_root_not_absolute"
    );
    let missing = tempfile::tempdir().unwrap().path().join("gone");
    assert_eq!(
        snapshot(&request(&missing, SnapshotMode::Content)).unwrap_err(),
        "workspace_snapshot_root_missing"
    );
}

#[test]
fn run_command_wraps_errors_and_rejects_unknown_fields() {
    assert!(run_command(b"{\"root\":\"/\",\"mode\":\"content\",\"extra\":1}").is_err());
    let reply = run_command(b"{\"root\":\"relative\",\"mode\":\"stat\"}").unwrap();
    assert_eq!(reply["ok"], false);
}

fn fake_git(dir: &Path, head: &str) {
    let git = dir.join(".git");
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("HEAD"), head).unwrap();
}

#[test]
fn git_head_is_read_from_loose_and_packed_refs_without_running_git() {
    let dir = project();
    let commit = "a".repeat(40);
    fake_git(dir.path(), "ref: refs/heads/main\n");
    fs::write(
        dir.path().join(".git/refs/heads/main"),
        format!("{commit}\n"),
    )
    .unwrap();
    let loose = content(dir.path());
    assert_eq!(loose["git"]["head_commit"], commit.as_str());
    assert_eq!(loose["git"]["head_ref"], "refs/heads/main");
    assert_eq!(loose["git"]["linked_worktree"], false);
    assert_eq!(loose["excluded"]["directories"], 1);

    let packed = "b".repeat(40);
    fs::remove_file(dir.path().join(".git/refs/heads/main")).unwrap();
    fs::write(
        dir.path().join(".git/packed-refs"),
        format!("# pack-refs with: peeled\n{packed} refs/heads/main\n"),
    )
    .unwrap();
    let from_pack = content(dir.path());
    assert_eq!(from_pack["git"]["head_commit"], packed.as_str());
    assert_ne!(digest(&loose), digest(&from_pack));
}

#[test]
fn unsafe_head_refs_are_ignored() {
    let dir = project();
    fake_git(dir.path(), "ref: refs/../../etc/passwd\n");
    let result = content(dir.path());
    assert!(result["git"]["head_ref"].is_null());
    assert!(result["git"]["head_commit"].is_null());
}

#[test]
fn linked_worktrees_share_a_codebase_but_not_a_worktree_or_snapshot() {
    let main = project();
    let commit = "c".repeat(40);
    fake_git(main.path(), "ref: refs/heads/main\n");
    fs::write(
        main.path().join(".git/refs/heads/main"),
        format!("{commit}\n"),
    )
    .unwrap();
    let admin = main.path().join(".git/worktrees/feature");
    fs::create_dir_all(&admin).unwrap();
    fs::write(admin.join("commondir"), "../..\n").unwrap();
    fs::write(admin.join("HEAD"), format!("{commit}\n")).unwrap();

    let linked = project();
    fs::write(
        linked.path().join(".git"),
        format!("gitdir: {}\n", admin.to_str().unwrap()),
    )
    .unwrap();
    let main_result = content(main.path());
    let linked_result = content(linked.path());
    assert_eq!(main_result["codebase_key"], linked_result["codebase_key"]);
    assert_ne!(main_result["worktree_key"], linked_result["worktree_key"]);
    assert_eq!(linked_result["git"]["linked_worktree"], true);
    assert_eq!(linked_result["git"]["head_commit"], commit.as_str());
    assert_ne!(digest(&main_result), digest(&linked_result));
}

#[test]
fn depth_bound_reports_partial_coverage_and_records_the_cut() {
    let dir = project();
    let mut nested = dir.path().to_path_buf();
    for level in 0..=walk::MAX_WALK_DEPTH {
        nested.push(format!("d{level}"));
    }
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("deep.txt"), "deep").unwrap();
    let result = content(dir.path());
    assert_eq!(result["coverage"], "partial");
    assert_eq!(result["partial_reasons"], serde_json::json!(["depth_cap"]));
    assert_eq!(result["entry_count"], 2);
}

#[test]
fn visit_budget_counts_excluded_entries_and_reports_partial_coverage() {
    let dir = project();
    for index in 0..5 {
        fs::create_dir_all(dir.path().join(format!("node_modules{index}/node_modules"))).unwrap();
    }
    let mut capped = request(dir.path(), SnapshotMode::Content);
    capped.max_visited_entries = 4;
    let result = snapshot(&capped).unwrap();
    assert_eq!(result["coverage"], "partial");
    assert_eq!(result["partial_reasons"], serde_json::json!(["visit_cap"]));
    assert_eq!(result["limits"]["max_visited_entries"], 4);
}

#[cfg(unix)]
#[test]
fn every_exclusion_stays_in_the_digest_however_many_there_are() {
    let outside = tempfile::tempdir().unwrap();
    let dir = project();
    for index in 0..300 {
        std::os::unix::fs::symlink(
            outside.path().join("a"),
            dir.path().join(format!("l{index:03}")),
        )
        .unwrap();
    }
    let first = content(dir.path());
    fs::remove_file(dir.path().join("l299")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("b"), dir.path().join("l299")).unwrap();
    let retargeted = content(dir.path());
    assert_eq!(
        first["excluded"]["symlinks"],
        retargeted["excluded"]["symlinks"]
    );
    assert_ne!(digest(&first), digest(&retargeted));
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_after_classification_is_not_entered() {
    use std::ffi::OsStr;

    use crate::workspace_snapshot_file::{DirHandle, HashError, Kind};

    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), "outside").unwrap();
    let dir = project();
    let root = fs::canonicalize(dir.path()).unwrap();
    let handle = DirHandle::open_root(&root).unwrap();
    let seen = handle.stat(OsStr::new("src")).unwrap();
    assert_eq!(seen.kind, Kind::Directory);
    fs::rename(root.join("src"), root.join("src-moved")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("src")).unwrap();
    assert_eq!(
        handle.open_dir(OsStr::new("src"), &seen).err(),
        Some(HashError::Unstable)
    );
    // A different directory under the same name is rejected too.
    fs::remove_file(root.join("src")).unwrap();
    fs::create_dir(root.join("src")).unwrap();
    assert_eq!(
        handle.open_dir(OsStr::new("src"), &seen).err(),
        Some(HashError::Unstable)
    );
}
