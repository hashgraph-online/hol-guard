//! Inert Git-object check for a pinned Python-produced source archive.
//! The archived config and hooks are never installed or interpreted.

use crate::fixed_process::{run_fixed_clean, FixedProcessError};
use crate::source_archive::{verified_archive_bytes, SourceArchiveError, SourceArchiveInventory};
use flate2::read::MultiGzDecoder;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;

const GIT: &str = "/usr/bin/git";
const GIT_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceArchiveCommitError {
    Archive(SourceArchiveError),
    InvalidInput,
    MissingRef,
    InvalidRef,
    InvalidObjectPath,
    MissingObjects,
    Io,
    GitUnavailable,
    GitFailed,
    GitTimedOut,
}

impl fmt::Display for SourceArchiveCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(error) => write!(f, "{error}"),
            Self::InvalidInput => f.write_str("invalid outside source commit or ref"),
            Self::MissingRef => f.write_str("source archive lacks the exact expected ref"),
            Self::InvalidRef => f.write_str("source archive ref is not a single Git object ID"),
            Self::InvalidObjectPath => f.write_str("source archive has an invalid Git object path"),
            Self::MissingObjects => f.write_str("source archive lacks materialized Git objects"),
            Self::Io => f.write_str("private Git object inspection failed"),
            Self::GitUnavailable => f.write_str("fixed Git object reader is unavailable"),
            Self::GitFailed => f.write_str("archived Git graph or commit differs"),
            Self::GitTimedOut => f.write_str("archived Git graph check exceeded its deadline"),
        }
    }
}

impl std::error::Error for SourceArchiveCommitError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceArchiveCommitProof {
    job_id: String,
    archive: SourceArchiveInventory,
    source_sha: String,
    source_ref: String,
    ref_object_id: String,
    git_graph_verified: bool,
    execution_eligible: bool,
}

impl SourceArchiveCommitProof {
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn archive(&self) -> &SourceArchiveInventory {
        &self.archive
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    pub fn ref_object_id(&self) -> &str {
        &self.ref_object_id
    }

    pub fn git_graph_verified(&self) -> bool {
        self.git_graph_verified
    }

    pub fn execution_eligible(&self) -> bool {
        self.execution_eligible
    }
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn expected_ref(source_sha: &str, source_ref: &str) -> bool {
    matches!(source_ref, "refs/tags/v3.48.0" | "refs/tags/v3.49.0")
        || source_ref == format!("refs/heads/local-{source_sha}")
}

fn object_file(path: &str) -> Option<PathBuf> {
    let relative = path.strip_prefix("repository.git/objects/")?;
    let (first, second) = relative.split_once('/')?;
    if hex(first, 2) && hex(second, 38) {
        return Some(PathBuf::from(relative));
    }
    if first == "pack" {
        let (stem, extension) = second.rsplit_once('.')?;
        if let Some(digest) = stem.strip_prefix("pack-") {
            if hex(digest, 40) && matches!(extension, "pack" | "idx" | "rev") {
                return Some(PathBuf::from(relative));
            }
        }
    }
    None
}

fn map_git_error(error: FixedProcessError) -> SourceArchiveCommitError {
    match error {
        FixedProcessError::Unavailable => SourceArchiveCommitError::GitUnavailable,
        FixedProcessError::TimedOut => SourceArchiveCommitError::GitTimedOut,
        FixedProcessError::Failed | FixedProcessError::TooLarge => {
            SourceArchiveCommitError::GitFailed
        }
    }
}

fn git(git_dir: &Path, args: &[&str]) -> Result<Vec<u8>, SourceArchiveCommitError> {
    let mut argv = vec![GIT.to_owned(), format!("--git-dir={}", git_dir.display())];
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    let env = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_COUNT", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];
    run_fixed_clean(&argv, GIT_DEADLINE, 4096, 4096, &env).map_err(map_git_error)
}

fn materialize_object(
    entry: &mut tar::Entry<'_, MultiGzDecoder<&[u8]>>,
    destination: &Path,
) -> Result<(), SourceArchiveCommitError> {
    let parent = destination.parent().ok_or(SourceArchiveCommitError::Io)?;
    fs::create_dir_all(parent).map_err(|_| SourceArchiveCommitError::Io)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|_| SourceArchiveCommitError::Io)?;
    let copied = io::copy(entry, &mut out).map_err(|_| SourceArchiveCommitError::Io)?;
    if copied != entry.size() {
        return Err(SourceArchiveCommitError::Io);
    }
    out.flush().map_err(|_| SourceArchiveCommitError::Io)
}

/// Check that a pinned archive's exact ref resolves to the caller's commit and
/// that Git accepts its reachable object graph. Only object files and a
/// validated shallow boundary enter a fresh private repository; archived Git
/// config, hooks, refs, alternates and worktree data are never executed.
/// Source-host authenticity and the outside pins remain the caller's duty.
pub fn verify_retained_source_archive_commit(
    state: &Path,
    job_id: &str,
    archive_sha256: &str,
    source_sha: &str,
    source_ref: &str,
) -> Result<SourceArchiveCommitProof, SourceArchiveCommitError> {
    if !hex(source_sha, 40) || !expected_ref(source_sha, source_ref) {
        return Err(SourceArchiveCommitError::InvalidInput);
    }
    let (bytes, archive_inventory) = verified_archive_bytes(state, job_id, archive_sha256)
        .map_err(SourceArchiveCommitError::Archive)?;
    let scratch = tempfile::Builder::new()
        .prefix("gauntlet-archive-git-")
        .tempdir()
        .map_err(|_| SourceArchiveCommitError::Io)?;
    let git_dir = scratch.path().join("repository.git");
    fs::create_dir(&git_dir).map_err(|_| SourceArchiveCommitError::Io)?;
    fs::create_dir(git_dir.join("objects")).map_err(|_| SourceArchiveCommitError::Io)?;
    fs::create_dir(git_dir.join("refs")).map_err(|_| SourceArchiveCommitError::Io)?;
    fs::write(git_dir.join("HEAD"), b"ref: refs/heads/empty\n")
        .map_err(|_| SourceArchiveCommitError::Io)?;
    fs::write(
        git_dir.join("config"),
        b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
    )
    .map_err(|_| SourceArchiveCommitError::Io)?;

    let decoder = MultiGzDecoder::new(bytes.as_slice());
    let mut tar = Archive::new(decoder);
    let mut ref_oid = None;
    let mut object_files = 0usize;
    for member in tar.entries().map_err(|_| SourceArchiveCommitError::Io)? {
        let mut member = member.map_err(|_| SourceArchiveCommitError::Io)?;
        if !member.header().entry_type().is_file() {
            continue;
        }
        let path = member.path_bytes();
        let path =
            std::str::from_utf8(&path).map_err(|_| SourceArchiveCommitError::InvalidObjectPath)?;
        if path == format!("repository.git/{source_ref}") {
            let mut value = Vec::new();
            member
                .by_ref()
                .take(42)
                .read_to_end(&mut value)
                .map_err(|_| SourceArchiveCommitError::Io)?;
            if value.len() != 41 || value[40] != b'\n' {
                return Err(SourceArchiveCommitError::InvalidRef);
            }
            let oid = std::str::from_utf8(&value[..40])
                .map_err(|_| SourceArchiveCommitError::InvalidRef)?;
            if !hex(oid, 40) {
                return Err(SourceArchiveCommitError::InvalidRef);
            }
            ref_oid = Some(oid.to_owned());
        } else if path == "repository.git/shallow" {
            let mut value = Vec::new();
            member
                .by_ref()
                .take(4097)
                .read_to_end(&mut value)
                .map_err(|_| SourceArchiveCommitError::Io)?;
            if value.is_empty()
                || value.len() > 4096
                || !value.ends_with(b"\n")
                || value
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .any(|line| std::str::from_utf8(line).map_or(true, |oid| !hex(oid, 40)))
            {
                return Err(SourceArchiveCommitError::InvalidRef);
            }
            fs::write(git_dir.join("shallow"), value).map_err(|_| SourceArchiveCommitError::Io)?;
        } else if path.starts_with("repository.git/objects/") {
            if path == "repository.git/objects/info/packs" {
                continue;
            }
            let relative = object_file(path).ok_or(SourceArchiveCommitError::InvalidObjectPath)?;
            materialize_object(&mut member, &git_dir.join("objects").join(relative))?;
            object_files += 1;
        }
    }
    let ref_oid = ref_oid.ok_or(SourceArchiveCommitError::MissingRef)?;
    if object_files == 0 {
        return Err(SourceArchiveCommitError::MissingObjects);
    }
    let peeled = git(&git_dir, &["rev-parse", &format!("{ref_oid}^{{commit}}")])?;
    if peeled != format!("{source_sha}\n").as_bytes() {
        return Err(SourceArchiveCommitError::GitFailed);
    }
    git(
        &git_dir,
        &[
            "fsck",
            "--strict",
            "--no-reflogs",
            "--no-progress",
            "--no-dangling",
            &ref_oid,
        ],
    )?;
    Ok(SourceArchiveCommitProof {
        job_id: job_id.to_owned(),
        archive: archive_inventory,
        source_sha: source_sha.to_owned(),
        source_ref: source_ref.to_owned(),
        ref_object_id: ref_oid,
        git_graph_verified: true,
        execution_eligible: false,
    })
}
