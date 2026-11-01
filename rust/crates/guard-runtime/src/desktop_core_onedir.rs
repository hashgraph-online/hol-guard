//! `desktop-core-onedir --stdin`: unpack a downloaded onedir Desktop Core
//! archive for the updater.
//!
//! The archive's members are checked before anything is written, the pinned
//! `ditto` extracts it into the caller's empty directory, and the extracted
//! tree is walked again before the updater verifies its signatures:
//!
//! - R1: every member is a relative path under `hol-guard/`, without `..`,
//!   `.` or empty components, AppleDouble files or `__MACOSX`.
//! - R2: a symlink member names a short relative target that stays in the
//!   tree.
//! - R3: no member sits beneath a symlink member, and no two members fold to
//!   the same name, so extraction can never write through a link.
//! - R4: the launcher and the sealed-bundle anchors are regular members, and
//!   `_internal/` is not empty.
//! - R5: the extracted tree holds exactly the manifest's file count, links
//!   counted once and never followed.
//! - R6: every extracted link still resolves inside the tree.
//!
//! Any failure answers `unpacked: false`, which the updater reports as a
//! failed install.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

use crate::native_install_verdict::{Invocation, Runner, SystemRunner};

const SCHEMA: &str = "desktop-core-onedir.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const DITTO: &str = "/usr/bin/ditto";
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);
const TREE_ROOT: &str = "hol-guard";
const LAUNCHER: &str = "hol-guard/hol-guard";
const REQUIRED_MEMBERS: [&str; 3] = [
    LAUNCHER,
    "hol-guard/Info.plist",
    "hol-guard/_CodeSignature/CodeResources",
];
const INTERNAL_PREFIX: &str = "hol-guard/_internal/";
const LINK_TARGET_MAX: usize = 1024;
/// More entries than any onedir build ships; a larger archive or tree is
/// refused rather than walked without end.
const MAX_ENTRIES: usize = 200_000;
const MODE_MASK: u32 = 0o170000;
const SYMLINK_MODE: u32 = 0o120000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    archive: String,
    destination: String,
    file_count: u64,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "desktop-core-onedir"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "desktop_core_onedir_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("desktop_core_onedir_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request, &mut SystemRunner)?;
    serde_json::to_vec(&answer).map_err(|_| "desktop_core_onedir_response_unencodable".to_owned())
}

fn answer(request: &Request, runner: &mut impl Runner) -> Result<Value, String> {
    let archive = Path::new(&request.archive);
    let destination = Path::new(&request.destination);
    if request.schema != SCHEMA || !archive.is_absolute() || !destination.is_absolute() {
        return Err(invalid());
    }
    let unpacked = admitted(archive).is_some()
        && extracted(runner, archive, destination)
        && launcher_is_regular(destination)
        && tree_file_count(destination) == Some(request.file_count);
    Ok(json!({ "unpacked": unpacked }))
}

/// R1–R4 over the archive's central directory; `None` refuses it.
fn admitted(archive: &Path) -> Option<()> {
    let mut file = fs::File::open(archive).ok()?;
    let recorded = recorded_entries(&mut file)?;
    let mut zipped = ZipArchive::new(file).ok()?;
    // The reader keeps one entry per name, so a central directory that
    // records more entries than it lists carries a duplicate name.
    if zipped.len() > MAX_ENTRIES
        || recorded != zipped.len() as u64
        || zipped.has_overlapping_entries().ok()?
    {
        return None;
    }
    let mut names = BTreeSet::new();
    let mut links = BTreeSet::new();
    for index in 0..zipped.len() {
        let mut entry = zipped.by_index(index).ok()?;
        let name = std::str::from_utf8(entry.name_raw()).ok()?.to_owned();
        if !member_name_admitted(&name) {
            return None;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & MODE_MASK == SYMLINK_MODE)
        {
            let mut target = Vec::new();
            Read::take(&mut entry, LINK_TARGET_MAX as u64 + 1)
                .read_to_end(&mut target)
                .ok()?;
            if !link_target_admitted(&name, &target) {
                return None;
            }
            links.insert(name.clone());
        }
        if !names.insert(name) {
            return None;
        }
    }
    let folded: BTreeSet<Vec<String>> = names.iter().map(|name| fold(name)).collect();
    if folded.len() != names.len() {
        return None;
    }
    let folded_links: Vec<Vec<String>> = links.iter().map(|name| fold(name)).collect();
    let nested = names.iter().any(|name| {
        let parts = fold(name);
        folded_links
            .iter()
            .any(|link| link.len() < parts.len() && parts.starts_with(link))
    });
    if nested {
        return None;
    }
    let anchored = REQUIRED_MEMBERS
        .iter()
        .all(|member| names.contains(*member) && !links.contains(*member));
    let internal = names.iter().any(|name| name.starts_with(INTERNAL_PREFIX));
    (anchored && internal).then_some(())
}

/// The entry count the end-of-central-directory record (or its Zip64
/// record) declares; `None` when neither can be read.
fn recorded_entries(file: &mut fs::File) -> Option<u64> {
    const END_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const LOCATOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const ZIP64_END_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const END_LENGTH: usize = 22;
    const LOCATOR_LENGTH: usize = 20;
    let length = file.metadata().ok()?.len();
    let tail_length = length.min((END_LENGTH + usize::from(u16::MAX)) as u64);
    file.seek(SeekFrom::Start(length - tail_length)).ok()?;
    let mut tail = Vec::new();
    Read::take(&mut *file, tail_length)
        .read_to_end(&mut tail)
        .ok()?;
    let end = (0..=tail.len().checked_sub(END_LENGTH)?)
        .rev()
        .find(|index| tail[*index..*index + 4] == END_SIGNATURE)?;
    let entries = u16::from_le_bytes([tail[end + 10], tail[end + 11]]);
    if entries != u16::MAX {
        return Some(u64::from(entries));
    }
    let locator = tail.get(end.checked_sub(LOCATOR_LENGTH)?..end)?;
    if locator[..4] != LOCATOR_SIGNATURE {
        return None;
    }
    let zip64_end = u64::from_le_bytes(locator[8..16].try_into().ok()?);
    file.seek(SeekFrom::Start(zip64_end)).ok()?;
    let mut record = [0u8; 40];
    file.read_exact(&mut record).ok()?;
    if record[..4] != ZIP64_END_SIGNATURE {
        return None;
    }
    Some(u64::from_le_bytes(record[32..40].try_into().ok()?))
}

/// R1 for one member name.
fn member_name_admitted(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    let Some((_, inner)) = parts.split_last() else {
        return false;
    };
    let base = parts.iter().rev().find(|part| !part.is_empty());
    !name.starts_with('/')
        && !parts.iter().any(|part| *part == ".." || *part == ".")
        && !inner.iter().any(|part| part.is_empty())
        && (name == TREE_ROOT || name.starts_with("hol-guard/"))
        && !base.is_some_and(|base| base.starts_with("._"))
        && !parts.contains(&"__MACOSX")
}

/// R2 (and R6, for an extracted link): a non-empty, short, relative target
/// that resolves, beside `name`, to a path inside the tree.
fn link_target_admitted(name: &str, target: &[u8]) -> bool {
    if target.is_empty() || target.len() > LINK_TARGET_MAX || target.contains(&0) {
        return false;
    }
    let Ok(target) = std::str::from_utf8(target) else {
        return false;
    };
    if target.starts_with('/') {
        return false;
    }
    let joined = match name.rsplit_once('/') {
        Some((directory, _)) if !directory.is_empty() => format!("{directory}/{target}"),
        _ => target.to_owned(),
    };
    normalized(&joined).starts_with("hol-guard/")
}

/// `posixpath.normpath` for a relative path: `.` and empty components drop
/// and `..` removes the component before it.
fn normalized(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    parts.join("/")
}

/// The member name as the filesystem may compare it: NFC, case folded,
/// without trailing slashes, split into components.
fn fold(name: &str) -> Vec<String> {
    let composed: String = name.trim_end_matches('/').nfc().collect();
    caseless::default_case_fold_str(&composed)
        .split('/')
        .map(str::to_owned)
        .collect()
}

fn extracted(runner: &mut impl Runner, archive: &Path, destination: &Path) -> bool {
    let (Some(archive), Some(destination)) = (archive.to_str(), destination.to_str()) else {
        return false;
    };
    let invocation = Invocation {
        program: DITTO.to_owned(),
        arguments: ["-x", "-k", archive, destination]
            .iter()
            .map(|item| (*item).to_owned())
            .collect(),
        context: None,
        timeout: EXTRACT_TIMEOUT,
    };
    runner.run(&invocation).is_ok_and(|ran| ran.success)
}

fn launcher_is_regular(destination: &Path) -> bool {
    fs::symlink_metadata(destination.join(LAUNCHER)).is_ok_and(|metadata| metadata.is_file())
}

/// R5/R6: the regular files and links under `extracted`, which must all sit
/// in the tree root; links are counted once, checked and never followed.
fn tree_file_count(extracted: &Path) -> Option<u64> {
    let tree = fs::canonicalize(extracted.join(TREE_ROOT)).ok()?;
    let mut count = 0u64;
    let mut seen = 0usize;
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(extracted.to_path_buf(), Vec::new())];
    while let Some((directory, relative)) = pending.pop() {
        for entry in fs::read_dir(&directory).ok()? {
            let entry = entry.ok()?;
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let mut parts = relative.clone();
            parts.push(entry.file_name().into_string().ok()?);
            if parts[0] != TREE_ROOT {
                return None;
            }
            let kind = entry.file_type().ok()?;
            if kind.is_symlink() {
                if !link_admitted(&entry.path(), &parts.join("/"), &tree) {
                    return None;
                }
                count += 1;
            } else if kind.is_dir() {
                pending.push((entry.path(), parts));
            } else if kind.is_file() {
                count += 1;
            } else {
                return None;
            }
        }
    }
    Some(count)
}

/// R6 for one extracted link: its target passes R2 and the link resolves to
/// an existing path inside the tree.
fn link_admitted(link: &Path, relative: &str, tree: &Path) -> bool {
    let Ok(target) = fs::read_link(link) else {
        return false;
    };
    let Some(target) = target.to_str() else {
        return false;
    };
    link_target_admitted(relative, target.as_bytes())
        && fs::canonicalize(link)
            .is_ok_and(|resolved| resolved != tree && resolved.starts_with(tree))
}

fn invalid() -> String {
    "desktop_core_onedir_request_invalid".to_owned()
}

#[cfg(test)]
#[path = "desktop_core_onedir_tests.rs"]
mod tests;
