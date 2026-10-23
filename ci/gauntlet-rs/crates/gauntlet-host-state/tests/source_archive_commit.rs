use flate2::write::GzEncoder;
use flate2::Compression;
use gauntlet_host_state::{
    transfer_source_archive_one_use, verify_retained_source_archive_commit, ReleaseSourceError,
    SourceArchiveCommitError, TagLookupPlan, VmSourceTransferError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, Permissions};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::{Builder, Header};
use tempfile::TempDir;

const JOB_ID: &str = "0123456789abcdef";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureMode {
    Direct,
    Shallow,
    Annotated,
}

fn git(args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn add_file(tar: &mut Builder<GzEncoder<Vec<u8>>>, name: &str, bytes: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, name, Cursor::new(bytes))
        .unwrap();
}

fn add_directory(tar: &mut Builder<GzEncoder<Vec<u8>>>, root: &Path, directory: &Path) {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            add_directory(tar, root, &path);
        } else {
            let relative = path.strip_prefix(root).unwrap();
            // A newer Git may leave an auto-maintenance lock in its object
            // directory. It is not an object and must not enter the fixture.
            if relative == Path::new("objects/maintenance.lock") {
                continue;
            }
            let name = format!("repository.git/{}", relative.display());
            add_file(tar, &name, &fs::read(&path).unwrap());
        }
    }
}

fn fixture_object_paths(temp: &TempDir) -> Vec<String> {
    fn visit(root: &Path, directory: &Path, names: &mut Vec<String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, names);
            } else {
                names.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    let root = temp.path().join("repository.git");
    let mut names = Vec::new();
    visit(&root, &root.join("objects"), &mut names);
    names.sort();
    names
}

fn fixture(mode: FixtureMode, extra: Option<(&str, &[u8])>) -> (TempDir, PathBuf, String, String) {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("source");
    let bare = temp.path().join("repository.git");
    let repo_name = repo.to_str().unwrap();
    let bare_name = bare.to_str().unwrap();
    git(&["init", "-q", repo_name]);
    fs::write(repo.join("README"), b"source-bound fixture\n").unwrap();
    git(&["-C", repo_name, "add", "README"]);
    git(&[
        "-C",
        repo_name,
        "-c",
        "user.name=Gauntlet Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "Fixture",
    ]);
    if mode == FixtureMode::Shallow {
        fs::write(repo.join("README"), b"second source-bound fixture\n").unwrap();
        git(&["-C", repo_name, "add", "README"]);
        git(&[
            "-C",
            repo_name,
            "-c",
            "user.name=Gauntlet Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Second fixture",
        ]);
    }
    let source_sha = git(&["-C", repo_name, "rev-parse", "HEAD"]);
    if mode == FixtureMode::Annotated {
        git(&[
            "-C",
            repo_name,
            "-c",
            "user.name=Gauntlet Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "tag",
            "-a",
            "v3.49.0",
            "-m",
            "Annotated fixture",
        ]);
    }
    git(&["init", "-q", "--bare", "--template=", bare_name]);
    let mut fetch = vec![
        format!("--git-dir={bare_name}"),
        "fetch".to_owned(),
        "--no-tags".to_owned(),
    ];
    if mode == FixtureMode::Shallow {
        fetch.push("--depth=1".to_owned());
        fetch.push(format!("file://{repo_name}"));
    } else {
        fetch.push(repo_name.to_owned());
    }
    fetch.push(if mode == FixtureMode::Annotated {
        "refs/tags/v3.49.0:refs/tags/v3.49.0".to_owned()
    } else {
        format!("{source_sha}:refs/tags/v3.49.0")
    });
    git(&fetch.iter().map(String::as_str).collect::<Vec<_>>());
    if mode == FixtureMode::Shallow {
        assert!(bare.join("shallow").is_file());
    }
    let state = temp.path().join("state");
    let mut path = state.clone();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    for part in ["private", "local-builds", JOB_ID] {
        path.push(part);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    }
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(encoder);
    add_directory(&mut tar, &bare, &bare);
    if let Some((name, bytes)) = extra {
        add_file(&mut tar, name, bytes);
    }
    let bytes = tar.into_inner().unwrap().finish().unwrap();
    let archive_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let archive = path.join("source.tar.gz");
    fs::write(&archive, bytes).unwrap();
    fs::set_permissions(&archive, Permissions::from_mode(0o600)).unwrap();
    (
        temp,
        fs::canonicalize(state).unwrap(),
        source_sha,
        archive_sha256,
    )
}

#[test]
fn exact_ref_and_reachable_git_graph_verify_without_execution() {
    let (temp, state, sha, archive_sha) = fixture(FixtureMode::Direct, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error:?}; fixture objects: {:?}",
            fixture_object_paths(&temp)
        )
    });
    assert_eq!(proof.source_sha(), sha);
    assert_eq!(proof.ref_object_id(), sha);
    assert_eq!(proof.archive().archive_sha256, archive_sha);
    assert!(proof.git_graph_verified());
    assert!(!proof.execution_eligible());
}

#[test]
fn wrong_commit_and_missing_ref_refuse() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Direct, None);
    let wrong = format!(
        "{}{}",
        if sha.starts_with('0') { '1' } else { '0' },
        &sha[1..]
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &wrong,
            "refs/tags/v3.49.0"
        ),
        Err(SourceArchiveCommitError::GitFailed)
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &sha,
            "refs/tags/v3.48.0"
        ),
        Err(SourceArchiveCommitError::MissingRef)
    );
}

#[test]
fn archived_object_alternate_refuses() {
    let (_temp, state, sha, archive_sha) = fixture(
        FixtureMode::Direct,
        Some((
            "repository.git/objects/info/alternates",
            b"/outside/object-store\n",
        )),
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &sha,
            "refs/tags/v3.49.0"
        ),
        Err(SourceArchiveCommitError::InvalidObjectPath)
    );
}

#[test]
fn archived_maintenance_lock_refuses() {
    let (_temp, state, sha, archive_sha) = fixture(
        FixtureMode::Direct,
        Some(("repository.git/objects/maintenance.lock", b"stale\n")),
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &sha,
            "refs/tags/v3.49.0"
        ),
        Err(SourceArchiveCommitError::InvalidObjectPath)
    );
}

#[test]
fn shallow_fetch_graph_verifies() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Shallow, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    assert!(proof.git_graph_verified());
    assert!(!proof.execution_eligible());
}

#[test]
fn annotated_tag_peels_to_exact_commit() {
    let (temp, state, sha, archive_sha) = fixture(FixtureMode::Annotated, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error:?}; fixture objects: {:?}",
            fixture_object_paths(&temp)
        )
    });
    assert_ne!(proof.ref_object_id(), sha);
    assert!(proof.git_graph_verified());
}

#[test]
fn archive_proof_and_tag_recheck_bind_same_commit() {
    let (temp, state, sha, archive_sha) = fixture(FixtureMode::Shallow, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    let fake_git = temp.path().join("fixed-git");
    fs::write(
        &fake_git,
        format!("#!/bin/sh\nprintf '%s\\t%s\\n' {sha} refs/tags/v3.49.0\n"),
    )
    .unwrap();
    fs::set_permissions(&fake_git, Permissions::from_mode(0o700)).unwrap();
    let mut operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    operations["git"] = fake_git.to_str().unwrap().into();
    let plan = TagLookupPlan::new(&operations, "v3.49.0").unwrap();
    let rechecked = plan.recheck_archive_commit_read_only(&proof).unwrap();
    assert_eq!(rechecked["source_sha"], sha);
    assert_eq!(rechecked["source_archive_sha256"], archive_sha);
    assert_eq!(rechecked["tag_unchanged"], true);
    assert_eq!(rechecked["execution_eligible"], false);
    let wrong_plan = TagLookupPlan::new(&operations, "v3.48.0").unwrap();
    assert_eq!(
        wrong_plan.recheck_archive_commit_read_only(&proof),
        Err(ReleaseSourceError::ArchiveBinding)
    );
    fs::write(
        &fake_git,
        "#!/bin/sh\nprintf '%s\\t%s\\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v3.49.0\n",
    )
    .unwrap();
    assert_eq!(
        plan.recheck_archive_commit_read_only(&proof),
        Err(ReleaseSourceError::MovedTag)
    );
}

#[test]
fn one_use_streamed_transfer_rechecks_tag_and_refuses_replay() {
    let (temp, state, sha, archive_sha) = fixture(FixtureMode::Shallow, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    let guest = temp.path().join("guest");
    fs::create_dir(&guest).unwrap();
    let fake_lima = temp.path().join("fake-limactl");
    fs::write(
        &fake_lima,
        b"#!/bin/sh\n[ \"$1\" = shell ] || exit 9\n[ \"$3\" = -- ] || exit 9\nshift 3\nexec \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_lima, Permissions::from_mode(0o700)).unwrap();
    let fake_git = temp.path().join("fixed-git");
    fs::write(
        &fake_git,
        format!("#!/bin/sh\nprintf '%s\\t%s\\n' {sha} refs/tags/v3.49.0\n"),
    )
    .unwrap();
    fs::set_permissions(&fake_git, Permissions::from_mode(0o700)).unwrap();
    let mut operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    operations["limactl"] = fake_lima.to_str().unwrap().into();
    operations["guest_inbox"] = guest.to_str().unwrap().into();
    operations["git"] = fake_git.to_str().unwrap().into();

    fs::write(
        &fake_git,
        "#!/bin/sh\nprintf '%s\\t%s\\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v3.49.0\n",
    )
    .unwrap();
    assert_eq!(
        transfer_source_archive_one_use(&state, &operations, &proof),
        Err(VmSourceTransferError::ReleaseTag(
            ReleaseSourceError::MovedTag
        ))
    );
    assert!(fs::read_dir(&guest).unwrap().next().is_none());

    fs::write(
        &fake_git,
        format!("#!/bin/sh\nprintf '%s\\t%s\\n' {sha} refs/tags/v3.49.0\n"),
    )
    .unwrap();
    let transferred = transfer_source_archive_one_use(&state, &operations, &proof).unwrap();
    assert_eq!(transferred.archive_sha256(), archive_sha);
    assert!(!transferred.execution_eligible());
    let guest_bytes = fs::read(transferred.guest_path()).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&guest_bytes)), archive_sha);
    assert_eq!(
        transfer_source_archive_one_use(&state, &operations, &proof),
        Err(VmSourceTransferError::GuestUncertain)
    );
    assert_eq!(fs::read(transferred.guest_path()).unwrap(), guest_bytes);
}
