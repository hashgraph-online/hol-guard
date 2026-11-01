use std::os::unix::fs::PermissionsExt;

use super::super::{run_command, SCHEMA};
use super::*;

fn run(request: Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn backup_request(directory: &Path, harness: &str, files: &[&Path], skip: &[&Path]) -> Value {
    json!({
        "schema": SCHEMA,
        "op": "backup",
        "backup_dir": directory,
        "harness": harness,
        "candidates": files,
        "skip": skip,
    })
}

fn finalize_request(directory: &Path, entries: &Value) -> Value {
    json!({
        "schema": SCHEMA,
        "op": "finalize-backups",
        "backup_dir": directory,
        "stamp": "20261101T000000Z",
        "entries": entries,
    })
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[test]
fn backup_copies_existing_files_owner_only() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = root.path().join("settings.json");
    fs::write(&settings, b"{\"hooks\": {}}").expect("write settings");
    let missing = root.path().join("missing.json");
    let directory = root.path().join("backups").join("hook-removal-1");

    let answer = run(backup_request(
        &directory,
        "claude-code",
        &[&settings, &missing],
        &[],
    ))
    .expect("backup answer");

    assert_eq!(answer["outcome"], "ok");
    let entries = answer["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["harness"], "claude-code");
    assert_eq!(entry["original_path"], settings.to_str().expect("utf-8"));
    let copy = PathBuf::from(entry["backup_path"].as_str().expect("backup path"));
    assert_eq!(copy.parent(), Some(directory.as_path()));
    let tag = &hex::encode(Sha256::digest(settings.to_str().expect("utf-8").as_bytes()))[..8];
    assert_eq!(
        copy.file_name().and_then(|name| name.to_str()),
        Some(format!("claude-code-{tag}-settings.json").as_str())
    );
    assert_eq!(fs::read(&copy).expect("copy"), b"{\"hooks\": {}}");
    assert_eq!(
        entry["sha256"],
        hex::encode(Sha256::digest(b"{\"hooks\": {}}"))
    );
    assert_eq!(mode(&directory), 0o700);
    assert_eq!(mode(&copy), 0o600);
}

#[test]
fn backup_skips_files_an_earlier_harness_already_copied() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = root.path().join("settings.json");
    fs::write(&settings, b"{}").expect("write settings");
    let directory = root.path().join("backups");

    let answer = run(backup_request(
        &directory,
        "cursor",
        &[&settings],
        &[&settings],
    ))
    .expect("backup answer");

    assert_eq!(answer, json!({ "outcome": "ok", "entries": [] }));
    assert!(!directory.exists());
}

#[test]
fn a_failed_copy_removes_this_harness_copies_and_reports_the_error() {
    let root = tempfile::tempdir().expect("tempdir");
    let first = root.path().join("a.json");
    let second = root.path().join("b.json");
    fs::write(&first, b"{}").expect("write first");
    fs::write(&second, b"{}").expect("write second");
    let directory = root.path().join("backups");
    fs::create_dir(&directory).expect("backup dir");
    // A copy already sitting at the second target makes `create_new` fail.
    let tag = &hex::encode(Sha256::digest(second.to_str().expect("utf-8").as_bytes()))[..8];
    fs::write(directory.join(format!("codex-{tag}-b.json")), b"planted").expect("plant");

    let answer =
        run(backup_request(&directory, "codex", &[&first, &second], &[])).expect("backup answer");

    assert_eq!(answer["outcome"], "error");
    assert!(answer["error"]
        .as_str()
        .expect("error text")
        .starts_with("backup_failed: "));
    let left: Vec<String> = fs::read_dir(&directory)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(left, vec![format!("codex-{tag}-b.json")]);
}

#[test]
fn backup_refuses_a_backup_directory_that_is_not_a_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let settings = root.path().join("settings.json");
    fs::write(&settings, b"{}").expect("write settings");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("elsewhere");
    let link = root.path().join("backups");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
    let blocked = root.path().join("file");
    fs::write(&blocked, b"").expect("file");

    for directory in [link, blocked.join("backups")] {
        let answer =
            run(backup_request(&directory, "codex", &[&settings], &[])).expect("backup answer");
        assert_eq!(answer["outcome"], "error", "{}", directory.display());
    }
    assert_eq!(fs::read_dir(&elsewhere).expect("list").count(), 0);
}

#[test]
fn backup_follows_a_symlinked_config_to_copy_what_the_harness_reads() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("dotfiles.json");
    fs::write(&target, b"{\"a\": 1}").expect("target");
    let link = root.path().join("settings.json");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let directory = root.path().join("backups");

    let answer = run(backup_request(&directory, "codex", &[&link], &[])).expect("backup answer");

    let copy = answer["entries"][0]["backup_path"].as_str().expect("copy");
    assert_eq!(fs::read(copy).expect("copy"), b"{\"a\": 1}");
    assert!(!fs::symlink_metadata(copy)
        .expect("lstat")
        .file_type()
        .is_symlink());
}

#[test]
fn finalize_keeps_only_copies_of_changed_files_and_writes_a_manifest() {
    let root = tempfile::tempdir().expect("tempdir");
    let changed = root.path().join("changed.json");
    let untouched = root.path().join("untouched.json");
    fs::write(&changed, b"before").expect("changed");
    fs::write(&untouched, b"same").expect("untouched");
    let directory = root.path().join("backups");
    let answer = run(backup_request(
        &directory,
        "codex",
        &[&changed, &untouched],
        &[],
    ))
    .expect("backup answer");
    fs::write(&changed, b"after").expect("edit");

    let finalized = run(finalize_request(&directory, &answer["entries"])).expect("finalize");

    let copy = answer["entries"][0]["backup_path"].clone();
    let expected = json!([{
        "harness": "codex",
        "original_path": changed.to_str().expect("utf-8"),
        "backup_path": copy,
    }]);
    assert_eq!(finalized["files"], expected);
    assert_eq!(finalized["backup_dir"], directory.to_str().expect("utf-8"));
    assert!(!Path::new(answer["entries"][1]["backup_path"].as_str().expect("copy")).exists());
    let manifest: Value =
        serde_json::from_slice(&fs::read(directory.join(MANIFEST_NAME)).expect("manifest"))
            .expect("manifest JSON");
    assert_eq!(
        manifest,
        json!({ "created_at": "20261101T000000Z", "files": expected })
    );
    assert_eq!(mode(&directory.join(MANIFEST_NAME)), 0o600);
}

#[test]
fn finalize_with_nothing_changed_removes_the_backup_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let untouched = root.path().join("untouched.json");
    fs::write(&untouched, b"same").expect("untouched");
    let directory = root.path().join("backups");
    let answer = run(backup_request(&directory, "codex", &[&untouched], &[])).expect("backup");

    let finalized = run(finalize_request(&directory, &answer["entries"])).expect("finalize");

    assert_eq!(finalized, json!({ "backup_dir": null, "files": [] }));
    assert!(!directory.exists());
}

#[test]
fn a_deleted_original_keeps_its_copy() {
    let root = tempfile::tempdir().expect("tempdir");
    let removed = root.path().join("removed.json");
    fs::write(&removed, b"gone soon").expect("removed");
    let directory = root.path().join("backups");
    let answer = run(backup_request(&directory, "codex", &[&removed], &[])).expect("backup");
    fs::remove_file(&removed).expect("delete");

    let finalized = run(finalize_request(&directory, &answer["entries"])).expect("finalize");

    assert_eq!(finalized["files"].as_array().map(Vec::len), Some(1));
}

#[test]
fn finalize_never_removes_a_file_outside_the_backup_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let original = root.path().join("settings.json");
    fs::write(&original, b"same").expect("original");
    let directory = root.path().join("backups");
    let entries = json!([{
        "harness": "codex",
        "original_path": original,
        "backup_path": original,
        "sha256": hex::encode(Sha256::digest(b"same")),
    }]);

    assert_eq!(
        run(finalize_request(&directory, &entries)),
        Err("hook_removal_sweep_request_invalid".to_owned())
    );
    assert!(original.exists());
}

#[test]
fn malformed_backup_requests_are_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = root.path().join("backups");
    let settings = root.path().join("settings.json");
    let invalid = Err("hook_removal_sweep_request_invalid".to_owned());
    for harness in ["", "../x", ".hidden", "a/b"] {
        assert_eq!(
            run(backup_request(&directory, harness, &[&settings], &[])),
            invalid,
            "{harness:?}"
        );
    }
    let mut relative = backup_request(&directory, "codex", &[&settings], &[]);
    relative["backup_dir"] = json!("backups");
    assert_eq!(run(relative), invalid);
    let mut stamped = backup_request(&directory, "codex", &[&settings], &[]);
    stamped["stamp"] = json!("x");
    assert_eq!(run(stamped), invalid);
    let sweep_with_backup = json!({
        "schema": SCHEMA, "op": "sweep", "candidates": [], "backup_dir": directory,
    });
    assert_eq!(run(sweep_with_backup), invalid);
}
