//! Read-only Git-object provenance check for a proposed controller install.
//! A caller supplies an outside commit and complete expected source hash map;
//! this diagnostic never fetches, checks out, installs or runs those bytes.

use crate::fixed_process::{run_fixed, FixedProcessError};
use gauntlet_contracts::canonical_relative_asset_path;
use gauntlet_evidence::plan_controller_install;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

const GIT: &str = "/usr/bin/git";
const MAX_FILES: usize = 2046;
const MAX_TREE_BYTES: usize = 256 * 1024;
const MAX_BLOB_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(90);
const ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_TERMINAL_PROMPT", "0"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitControllerSourceError {
    InvalidInput,
    GitUnavailable,
    GitFailed,
    TimedOut,
    TooLarge,
    WrongCommitType,
    InvalidTree,
    SourceMapMismatch,
    BlobMismatch,
    InstallPlan,
}

impl fmt::Display for GitControllerSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid repository, commit or outside source map",
            Self::GitUnavailable => "fixed Git object reader is unavailable",
            Self::GitFailed => "fixed Git object read failed",
            Self::TimedOut => "fixed Git object read exceeded its deadline",
            Self::TooLarge => "Git controller source exceeds its byte limit",
            Self::WrongCommitType => "outside SHA does not identify a commit object",
            Self::InvalidTree => "Git controller tree has an invalid path, type or mode",
            Self::SourceMapMismatch => "Git controller paths differ from the outside source map",
            Self::BlobMismatch => "Git controller blob differs from its outside SHA-256",
            Self::InstallPlan => "Git controller source cannot form the fixed install plan",
        })
    }
}

impl std::error::Error for GitControllerSourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitControllerSourceProof {
    pub source_sha: String,
    pub files: usize,
    pub bytes: usize,
    pub installed_files: usize,
    pub controller_tree_digest: String,
}

impl GitControllerSourceProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-git-controller-source-shadow.v1",
            "source_sha":self.source_sha,
            "source_files":self.files,
            "source_bytes":self.bytes,
            "installed_files":self.installed_files,
            "controller_tree_digest":self.controller_tree_digest,
            "outside_pin_provenance_verified":false,
            "execution_eligible":false,
        })
    }
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_path(path: &str) -> bool {
    (path == "ci/__init__.py" || path.starts_with("ci/gauntlet/"))
        && canonical_relative_asset_path(path)
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

fn map_process_error(error: FixedProcessError) -> GitControllerSourceError {
    match error {
        FixedProcessError::Unavailable => GitControllerSourceError::GitUnavailable,
        FixedProcessError::Failed => GitControllerSourceError::GitFailed,
        FixedProcessError::TimedOut => GitControllerSourceError::TimedOut,
        FixedProcessError::TooLarge => GitControllerSourceError::TooLarge,
    }
}

fn git_argv(repository: &Path, args: &[&str]) -> Vec<String> {
    let mut argv = vec![
        GIT.to_owned(),
        "-C".to_owned(),
        repository.to_string_lossy().into_owned(),
        "-c".to_owned(),
        "core.hooksPath=/dev/null".to_owned(),
        "-c".to_owned(),
        "gc.auto=0".to_owned(),
    ];
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    argv
}

fn run_git(
    repository: &Path,
    args: &[&str],
    limit: usize,
    started: Instant,
) -> Result<Vec<u8>, GitControllerSourceError> {
    let remaining = DEADLINE
        .checked_sub(started.elapsed())
        .ok_or(GitControllerSourceError::TimedOut)?;
    run_fixed(
        &git_argv(repository, args),
        remaining.min(Duration::from_secs(5)),
        limit,
        1500,
        ENV,
    )
    .map_err(map_process_error)
}

fn parse_tree(bytes: &[u8]) -> Result<BTreeMap<String, String>, GitControllerSourceError> {
    if bytes.is_empty() || bytes.len() > MAX_TREE_BYTES || !bytes.ends_with(&[0]) {
        return Err(GitControllerSourceError::InvalidTree);
    }
    let mut entries = BTreeMap::new();
    for row in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let separator = row
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(GitControllerSourceError::InvalidTree)?;
        let (head, path) = (&row[..separator], &row[separator + 1..]);
        let head = std::str::from_utf8(head).map_err(|_| GitControllerSourceError::InvalidTree)?;
        let path = std::str::from_utf8(path).map_err(|_| GitControllerSourceError::InvalidTree)?;
        let mut fields = head.split(' ');
        let mode = fields.next().ok_or(GitControllerSourceError::InvalidTree)?;
        let kind = fields.next().ok_or(GitControllerSourceError::InvalidTree)?;
        let oid = fields.next().ok_or(GitControllerSourceError::InvalidTree)?;
        if fields.next().is_some()
            || !matches!(mode, "100644" | "100755")
            || kind != "blob"
            || !hex(oid, 40)
            || !valid_path(path)
            || entries.insert(path.to_owned(), oid.to_owned()).is_some()
            || entries.len() > MAX_FILES
        {
            return Err(GitControllerSourceError::InvalidTree);
        }
    }
    if entries.is_empty() {
        return Err(GitControllerSourceError::InvalidTree);
    }
    Ok(entries)
}

/// Compare a complete controller-source tree at one exact local Git commit
/// with independently supplied path/SHA-256 pins, then derive the Python
/// bootstrap's expected Root-owned installed-tree digest. Git reads objects
/// only; the caller must still authenticate the pins, Git binary and repo.
pub fn verify_git_controller_source(
    repository: &Path,
    source_sha: &str,
    expected_source_hashes: &BTreeMap<String, String>,
) -> Result<GitControllerSourceProof, GitControllerSourceError> {
    if !repository.is_absolute()
        || !repository.is_dir()
        || !hex(source_sha, 40)
        || expected_source_hashes.is_empty()
        || expected_source_hashes.len() > MAX_FILES
        || expected_source_hashes
            .iter()
            .any(|(path, hash)| !valid_path(path) || !hex(hash, 64))
    {
        return Err(GitControllerSourceError::InvalidInput);
    }
    let started = Instant::now();
    let object_type = run_git(repository, &["cat-file", "-t", source_sha], 32, started)?;
    if object_type != b"commit\n" {
        return Err(GitControllerSourceError::WrongCommitType);
    }
    let tree_args = [
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        "--no-abbrev",
        source_sha,
        "--",
        "ci/__init__.py",
        "ci/gauntlet",
    ];
    let first_tree = run_git(repository, &tree_args, MAX_TREE_BYTES, started)?;
    let entries = parse_tree(&first_tree)?;
    if entries.len() != expected_source_hashes.len()
        || !entries.keys().eq(expected_source_hashes.keys())
    {
        return Err(GitControllerSourceError::SourceMapMismatch);
    }
    let mut total_bytes = 0usize;
    for (path, oid) in &entries {
        let blob = run_git(
            repository,
            &["cat-file", "blob", oid],
            MAX_BLOB_BYTES,
            started,
        )?;
        total_bytes = total_bytes
            .checked_add(blob.len())
            .filter(|bytes| *bytes <= MAX_TOTAL_BYTES)
            .ok_or(GitControllerSourceError::TooLarge)?;
        let actual = format!("{:x}", Sha256::digest(&blob));
        if expected_source_hashes.get(path) != Some(&actual) {
            return Err(GitControllerSourceError::BlobMismatch);
        }
    }
    let last_tree = run_git(repository, &tree_args, MAX_TREE_BYTES, started)?;
    if first_tree != last_tree {
        return Err(GitControllerSourceError::InvalidTree);
    }
    let install = plan_controller_install(expected_source_hashes)
        .map_err(|_| GitControllerSourceError::InstallPlan)?;
    Ok(GitControllerSourceProof {
        source_sha: source_sha.to_owned(),
        files: entries.len(),
        bytes: total_bytes,
        installed_files: install.installed_files.len(),
        controller_tree_digest: install.tree_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn git(repository: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new(GIT)
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    fn exact_git_blobs_match_and_a_changed_outside_pin_refuses() {
        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path();
        git(repository, &["init", "-q"]);
        let mut map = BTreeMap::new();
        for (path, bytes) in [
            ("ci/gauntlet/__init__.py", b"# package\n".as_slice()),
            (
                "ci/gauntlet/benchmark/__main__.py",
                b"# runner\n".as_slice(),
            ),
            (
                "ci/gauntlet/control_plane/bootstrap_guest.py",
                b"# installer\n".as_slice(),
            ),
        ] {
            let file = repository.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, bytes).unwrap();
            map.insert(path.to_owned(), format!("{:x}", Sha256::digest(bytes)));
        }
        git(repository, &["add", "--", "ci/gauntlet"]);
        git(
            repository,
            &[
                "-c",
                "user.name=Gauntlet test",
                "-c",
                "user.email=gauntlet@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "fixed source fixture",
            ],
        );
        let commit = String::from_utf8(git(repository, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        let proof = verify_git_controller_source(repository, &commit, &map).unwrap();
        assert_eq!(proof.files, 3);
        assert_eq!(proof.installed_files, 3);
        assert!(!proof.to_json()["execution_eligible"].as_bool().unwrap());
        map.insert("ci/gauntlet/__init__.py".to_owned(), "0".repeat(64));
        assert_eq!(
            verify_git_controller_source(repository, &commit, &map),
            Err(GitControllerSourceError::BlobMismatch)
        );
    }

    #[test]
    fn tree_parser_refuses_symlink_duplicate_and_unexpected_paths() {
        let oid = "1".repeat(40);
        let row = format!("100644 blob {oid}\tci/gauntlet/__init__.py\0");
        assert_eq!(parse_tree(row.as_bytes()).unwrap().len(), 1);
        let symlink = format!("120000 blob {oid}\tci/gauntlet/__init__.py\0");
        assert_eq!(
            parse_tree(symlink.as_bytes()),
            Err(GitControllerSourceError::InvalidTree)
        );
        let duplicate = format!("{row}{row}");
        assert_eq!(
            parse_tree(duplicate.as_bytes()),
            Err(GitControllerSourceError::InvalidTree)
        );
        let outside = format!("100644 blob {oid}\tci/gauntlet/../outside\0");
        assert_eq!(
            parse_tree(outside.as_bytes()),
            Err(GitControllerSourceError::InvalidTree)
        );
    }
}
