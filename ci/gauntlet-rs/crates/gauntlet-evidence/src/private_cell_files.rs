//! Root-owned private-cell artifact inventory. Candidate files remain inert.

use crate::crypto::sha256;
use crate::private_cell_manifest::{verify_private_cell_manifest, PrivateCellManifest};
use crate::{EvidenceError, Result};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const MAX_ENTRIES: usize = 256;
const MAX_FILES: usize = 128;
const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateCellInventory {
    pub manifest_sha256: String,
    pub files: BTreeMap<String, String>,
    pub bytes: usize,
    pub candidate_code_executed: bool,
}

fn trusted(stat: &Stat, directory: bool) -> bool {
    let kind = FileType::from_raw_mode(stat.st_mode);
    stat.st_uid == 0
        && stat.st_mode & 0o022 == 0
        && if directory {
            kind == FileType::Directory
        } else {
            kind == FileType::RegularFile
        }
}

fn unchanged(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn open_root(path: &Path) -> Result<OwnedFd> {
    let literal = path
        .to_str()
        .ok_or(EvidenceError::Invalid("non-UTF8 private-cell root"))?;
    if !path.is_absolute()
        || literal != "/"
            && !literal.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..")
            })
    {
        return Err(EvidenceError::Invalid(
            "canonical absolute private-cell root required",
        ));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            directory = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let stat = fstat(&directory).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if !trusted(&stat, true) {
                return Err(EvidenceError::Invalid(
                    "private-cell ancestor is not root-owned and immutable",
                ));
            }
        }
    }
    Ok(directory)
}

fn read_fixed(file: OwnedFd, before: &Stat) -> Result<Vec<u8>> {
    if !trusted(before, false) || before.st_size < 0 || before.st_size as usize > MAX_FILE_BYTES {
        return Err(EvidenceError::Invalid("unsafe private-cell artifact file"));
    }
    let mut file = File::from(file);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if raw.len() > MAX_FILE_BYTES
        || raw.len() as i64 != before.st_size
        || !unchanged(before, &after)
    {
        return Err(EvidenceError::Invalid(
            "private-cell artifact changed while reading",
        ));
    }
    Ok(raw)
}

fn scan(
    directory: &OwnedFd,
    prefix: &str,
    depth: usize,
    entries: &mut usize,
    total: &mut usize,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(EvidenceError::Invalid("private-cell artifact depth bound"));
    }
    let before = fstat(directory).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !trusted(&before, true) {
        return Err(EvidenceError::Invalid(
            "unsafe private-cell artifact directory",
        ));
    }
    let items = Dir::read_from(directory).map_err(|error| EvidenceError::Io(error.to_string()))?;
    for item in items {
        let item = item.map_err(|error| EvidenceError::Io(error.to_string()))?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| EvidenceError::Invalid("non-UTF8 private-cell artifact name"))?;
        if name == "." || name == ".." {
            continue;
        }
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(EvidenceError::Invalid("invalid private-cell artifact name"));
        }
        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(EvidenceError::Invalid("private-cell artifact entry bound"));
        }
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let observed = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let kind = FileType::from_raw_mode(observed.st_mode);
        match kind {
            FileType::Directory => {
                let child = openat(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
                let opened = fstat(&child).map_err(|error| EvidenceError::Io(error.to_string()))?;
                if !trusted(&opened, true) || !unchanged(&observed, &opened) {
                    return Err(EvidenceError::Invalid("changed private-cell directory"));
                }
                scan(&child, &relative, depth + 1, entries, total, files)?;
            }
            FileType::RegularFile => {
                let descriptor = openat(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
                let opened =
                    fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
                if !unchanged(&observed, &opened) {
                    return Err(EvidenceError::Invalid("changed private-cell artifact"));
                }
                let raw = read_fixed(descriptor, &opened)?;
                *total = total
                    .checked_add(raw.len())
                    .filter(|value| *value <= MAX_TOTAL_BYTES)
                    .ok_or(EvidenceError::Invalid("private-cell artifact byte bound"))?;
                if files.insert(relative, raw).is_some() || files.len() > MAX_FILES {
                    return Err(EvidenceError::Invalid("private-cell artifact file bound"));
                }
            }
            _ => return Err(EvidenceError::Invalid("nonregular private-cell artifact")),
        }
        let after = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        if !unchanged(&observed, &after) {
            return Err(EvidenceError::Invalid(
                "private-cell artifact changed during scan",
            ));
        }
    }
    let after = fstat(directory).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&before, &after) {
        return Err(EvidenceError::Invalid(
            "private-cell directory changed during scan",
        ));
    }
    Ok(())
}

fn compare_files(
    files: BTreeMap<String, Vec<u8>>,
    manifest: &PrivateCellManifest,
) -> Result<PrivateCellInventory> {
    let required: BTreeSet<_> = manifest
        .files
        .keys()
        .cloned()
        .chain(["manifest.json".to_owned()])
        .collect();
    if files.keys().cloned().collect::<BTreeSet<_>>() != required {
        return Err(EvidenceError::Invalid(
            "private-cell artifact directory has missing or extra files",
        ));
    }
    let mut observed = BTreeMap::new();
    let mut bytes = 0;
    for (name, pin) in &manifest.files {
        let raw = files
            .get(name)
            .ok_or(EvidenceError::Invalid("private-cell artifact missing"))?;
        bytes += raw.len();
        if sha256(raw) != *pin {
            return Err(EvidenceError::Invalid(
                "private-cell artifact differs from manifest",
            ));
        }
        observed.insert(name.clone(), pin.clone());
    }
    Ok(PrivateCellInventory {
        manifest_sha256: manifest.manifest_sha256.clone(),
        files: observed,
        bytes,
        candidate_code_executed: false,
    })
}

/// Verify the whole Root-owned private-cell artifact directory against outside
/// pins and this controller generation's embedded Python source. This reader
/// never imports or executes the files and cannot authorize a benchmark run.
pub fn verify_private_cell_artifacts(
    root: &Path,
    expected_manifest_sha256: &str,
    expected_initializer_sha256: &str,
) -> Result<PrivateCellInventory> {
    let root = open_root(root)?;
    let mut entries = 0;
    let mut total = 0;
    let mut files = BTreeMap::new();
    scan(&root, "", 0, &mut entries, &mut total, &mut files)?;
    let manifest_raw = files
        .get("manifest.json")
        .ok_or(EvidenceError::Invalid("private-cell manifest missing"))?;
    let manifest = verify_private_cell_manifest(
        manifest_raw,
        expected_manifest_sha256,
        expected_initializer_sha256,
    )?;
    compare_files(files, &manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unowned_artifact_root_cannot_enter_private_custody() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        if rustix::process::getuid().as_raw() != 0 {
            assert!(
                verify_private_cell_artifacts(&root, &"a".repeat(64), &"b".repeat(64)).is_err()
            );
        }
    }

    #[test]
    fn exact_file_set_and_file_hashes_are_required() {
        let mut pins = BTreeMap::new();
        pins.insert("public/actor.py".to_owned(), sha256(b"actor"));
        let manifest = PrivateCellManifest {
            manifest_sha256: "a".repeat(64),
            initializer_sha256: "b".repeat(64),
            files: pins,
        };
        let mut files = BTreeMap::new();
        files.insert("public/actor.py".to_owned(), b"actor".to_vec());
        files.insert(
            "manifest.json".to_owned(),
            serde_json::to_vec(&json!({})).unwrap(),
        );
        assert!(compare_files(files.clone(), &manifest).is_ok());
        files.insert("public/actor.py".to_owned(), b"changed".to_vec());
        assert!(compare_files(files.clone(), &manifest).is_err());
        files.remove("public/actor.py");
        assert!(compare_files(files, &manifest).is_err());
    }
}
