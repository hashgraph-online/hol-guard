//! One-use, source-matched private-cell artifact preparation. No cell runs.

use crate::builder_candidate_source::same_file;
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_shadow_assets::{private_directory, write_data};
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::{fixed_private_cell_sources, verify_private_cell_artifacts};
use rustix::fs::{fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const SHADOW_ROOT: &str = "/opt/hol-gauntlet/rust-shadow-candidates";
const TARGET: &str = "cell-artifacts";
const MAX_ACTOR: u64 = 2 * 1024 * 1024;
const MAX_INITIALIZER: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateCellShadowError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    ShadowMismatch,
    ExistingTarget,
    WriteUncertain,
    ReadbackMismatch,
}

impl fmt::Display for PrivateCellShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for private-cell artifact preparation",
            Self::InvalidPins => "exact private-cell outside pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "pinned old actor or initializer differs from source bytes",
            Self::ShadowMismatch => "one-use candidate shadow root unavailable",
            Self::ExistingTarget => "one-use private-cell artifact target already exists",
            Self::WriteUncertain => "private-cell artifact creation is incomplete or uncertain",
            Self::ReadbackMismatch => "private-cell artifact readback differs from current source",
        })
    }
}

impl std::error::Error for PrivateCellShadowError {}

#[derive(Debug, Clone, Copy)]
pub struct PrivateCellShadowPins<'a> {
    pub job_id: &'a str,
    pub source_artifacts: &'a str,
    pub actor_sha256: &'a str,
    pub initializer_sha256: &'a str,
    pub source_map_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateCellShadowProof {
    job_id: String,
    artifact_path: String,
    source_map_sha256: String,
    manifest_sha256: String,
    initializer_sha256: String,
    files: usize,
    bytes: usize,
}

impl PrivateCellShadowProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-private-cell-shadow-artifacts.v1",
            "job_id":self.job_id,
            "artifact_path":self.artifact_path,
            "source_map_sha256":self.source_map_sha256,
            "manifest_sha256":self.manifest_sha256,
            "initializer_sha256":self.initializer_sha256,
            "files":self.files,
            "bytes":self.bytes,
            "artifacts_verified_inert":true,
            "candidate_code_executed":false,
            "execution_eligible":false,
        })
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn source_bytes(
    root: &OwnedFd,
    name: &str,
    expected: &str,
    maximum: u64,
    mode: u32,
) -> Result<Vec<u8>, PrivateCellShadowError> {
    let public = openat(
        root,
        "public",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    let public_stat = fstat(&public).map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    if FileType::from_raw_mode(public_stat.st_mode) != FileType::Directory
        || public_stat.st_uid != 0
        || public_stat.st_gid != 0
        || public_stat.st_mode & 0o022 != 0
    {
        return Err(PrivateCellShadowError::SourceMismatch);
    }
    let descriptor = openat(
        &public,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    let before = fstat(&descriptor).map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != mode
        || before.st_size < 1
        || before.st_size as u64 > maximum
    {
        return Err(PrivateCellShadowError::SourceMismatch);
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut raw)
        .map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    let after = fstat(&file).map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    let visible = statat(&public, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    if raw.len() != before.st_size as usize
        || hash(&raw) != expected
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || !same_file(
            &public_stat,
            &fstat(&public).map_err(|_| PrivateCellShadowError::SourceMismatch)?,
        )
    {
        return Err(PrivateCellShadowError::SourceMismatch);
    }
    Ok(raw)
}

fn put_file(
    root: &OwnedFd,
    relative: &str,
    raw: &[u8],
    mode: u32,
) -> Result<(), PrivateCellShadowError> {
    let mut parts = relative.split('/').peekable();
    let mut directory = root
        .try_clone()
        .map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(PrivateCellShadowError::WriteUncertain);
        }
        if parts.peek().is_none() {
            write_data(&directory, part, raw, &hash(raw), mode)
                .map_err(|_| PrivateCellShadowError::WriteUncertain)?;
            break;
        }
        match mkdirat(&directory, part, Mode::from_bits_truncate(0o700)) {
            Ok(()) => fsync(&directory).map_err(|_| PrivateCellShadowError::WriteUncertain)?,
            Err(Errno::EXIST) => (),
            Err(_) => return Err(PrivateCellShadowError::WriteUncertain),
        }
        let next = openat(
            &directory,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PrivateCellShadowError::WriteUncertain)?;
        private_directory(&next).map_err(|_| PrivateCellShadowError::WriteUncertain)?;
        directory = next;
    }
    Ok(())
}

/// Create a fresh private artifact tree beside already copied inert candidate
/// assets. A partial target is retained on failure and never retried in place.
pub fn prepare_private_cell_shadow_artifacts_ineligible(
    pins: &PrivateCellShadowPins<'_>,
) -> Result<PrivateCellShadowProof, PrivateCellShadowError> {
    if geteuid().as_raw() != 0 {
        return Err(PrivateCellShadowError::RootRequired);
    }
    if !lower_hex(pins.job_id, 16)
        || !lower_hex(pins.actor_sha256, 64)
        || !lower_hex(pins.initializer_sha256, 64)
        || !lower_hex(pins.source_map_sha256, 64)
    {
        return Err(PrivateCellShadowError::InvalidPins);
    }
    let sources = fixed_private_cell_sources();
    let source_hashes: BTreeMap<_, _> = sources
        .iter()
        .map(|(name, raw)| (name.clone(), hash(raw)))
        .collect();
    let map_raw =
        serde_json::to_vec(&source_hashes).map_err(|_| PrivateCellShadowError::InvalidPins)?;
    let map_canonical = canonicalize(&map_raw).map_err(|_| PrivateCellShadowError::InvalidPins)?;
    if hash(&map_canonical) != pins.source_map_sha256 {
        return Err(PrivateCellShadowError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| PrivateCellShadowError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| PrivateCellShadowError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| PrivateCellShadowError::LeaseUnavailable)?;
    let source = open_root_owned_public_directory(Path::new(pins.source_artifacts))
        .map_err(|_| PrivateCellShadowError::SourceMismatch)?;
    let actor = source_bytes(&source, "actor.py", pins.actor_sha256, MAX_ACTOR, 0o444)?;
    let initializer = source_bytes(
        &source,
        "initializer",
        pins.initializer_sha256,
        MAX_INITIALIZER,
        0o555,
    )?;
    let shadow_path = Path::new(SHADOW_ROOT).join(pins.job_id);
    let shadow = open_root_owned_public_directory(&shadow_path)
        .map_err(|_| PrivateCellShadowError::ShadowMismatch)?;
    private_directory(&shadow).map_err(|_| PrivateCellShadowError::ShadowMismatch)?;
    match mkdirat(&shadow, TARGET, Mode::from_bits_truncate(0o700)) {
        Ok(()) => fsync(&shadow).map_err(|_| PrivateCellShadowError::WriteUncertain)?,
        Err(Errno::EXIST) => return Err(PrivateCellShadowError::ExistingTarget),
        Err(_) => return Err(PrivateCellShadowError::WriteUncertain),
    }
    let target = openat(
        &shadow,
        TARGET,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    private_directory(&target).map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    let mut files = source_hashes;
    for (name, raw) in &sources {
        put_file(&target, name, raw, 0o444)?;
    }
    put_file(&target, "public/actor.py", &actor, 0o444)?;
    put_file(&target, "public/initializer", &initializer, 0o555)?;
    files.insert("public/actor.py".into(), pins.actor_sha256.to_owned());
    files.insert(
        "public/initializer".into(),
        pins.initializer_sha256.to_owned(),
    );
    let manifest_raw =
        serde_json::to_vec(&json!({"schema":"product-cell-artifacts.v1","files":files}))
            .map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    let mut manifest =
        canonicalize(&manifest_raw).map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    manifest.push(b'\n');
    let manifest_sha = hash(&manifest);
    put_file(&target, "manifest.json", &manifest, 0o444)?;
    fsync(&target).map_err(|_| PrivateCellShadowError::WriteUncertain)?;
    let artifact_path = shadow_path.join(TARGET);
    let inventory =
        verify_private_cell_artifacts(&artifact_path, &manifest_sha, pins.initializer_sha256)
            .map_err(|_| PrivateCellShadowError::ReadbackMismatch)?;
    let source_after = source_bytes(&source, "actor.py", pins.actor_sha256, MAX_ACTOR, 0o444)?;
    let initializer_after = source_bytes(
        &source,
        "initializer",
        pins.initializer_sha256,
        MAX_INITIALIZER,
        0o555,
    )?;
    if source_after != actor || initializer_after != initializer {
        return Err(PrivateCellShadowError::SourceMismatch);
    }
    lease
        .verify(&journal.root)
        .map_err(|_| PrivateCellShadowError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| PrivateCellShadowError::LeaseUnavailable)?;
    Ok(PrivateCellShadowProof {
        job_id: pins.job_id.to_owned(),
        artifact_path: artifact_path.to_string_lossy().into_owned(),
        source_map_sha256: pins.source_map_sha256.to_owned(),
        manifest_sha256: manifest_sha,
        initializer_sha256: pins.initializer_sha256.to_owned(),
        files: inventory.files.len(),
        bytes: inventory.bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprivileged_writer_refuses_before_any_files() {
        if geteuid().as_raw() == 0 {
            return;
        }
        let pins = PrivateCellShadowPins {
            job_id: "",
            source_artifacts: "",
            actor_sha256: "",
            initializer_sha256: "",
            source_map_sha256: "",
        };
        assert!(matches!(
            prepare_private_cell_shadow_artifacts_ineligible(&pins),
            Err(PrivateCellShadowError::RootRequired)
        ));
    }
}
