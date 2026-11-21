//! Rust port of the filesystem half of `guard/skill_document_evidence.py`.
//!
//! A primary skill document is read once, under a ceiling, through a
//! descriptor that refuses to follow a symlink. What comes back describes the
//! document — its size, hash, shape and any network capability its prose
//! documents — and never its content. The text analysis itself lives in
//! `guard_command::skill_document_text_evidence`, where the parity vectors
//! pin it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::skill_document_text_evidence::analyze_skill_document_text;
use guard_contracts::{SkillDocumentEvidenceV1, SkillDocumentReadabilityV1};

/// Analysis ceiling, shared with the scanner that used to do this in Python.
pub(crate) const MAX_SKILL_DOCUMENT_BYTES: usize = 256 * 1024;

fn stopped(status: SkillDocumentReadabilityV1) -> SkillDocumentEvidenceV1 {
    SkillDocumentEvidenceV1 {
        readability_status: status,
        byte_length: None,
        content_hash: None,
        line_count: None,
        heading_count: None,
        frontmatter_present: None,
        documented_network_capability: None,
    }
}

fn stopped_with_size(
    status: SkillDocumentReadabilityV1,
    byte_length: u64,
) -> SkillDocumentEvidenceV1 {
    SkillDocumentEvidenceV1 {
        byte_length: Some(byte_length),
        ..stopped(status)
    }
}

/// Anchor a relative path to the caller's directory, the way the caller's own
/// filesystem calls would have resolved it. Absolute paths are untouched, and
/// no normalization happens here.
fn anchor(path: &Path, process_directory: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        process_directory.join(path)
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// Whether this path's last component is the expected name, compared the way
/// the Python reader compared it.
///
/// `str::casefold` there folds `\u{17f}` to `s`, which `to_lowercase` leaves
/// alone, so `\u{17f}KILL.md` named the primary document for the reader this
/// replaces. Upper-casing first reaches the same letter, and folds `\u{df}` to
/// `ss` the same way, so the two readers agree on which file is primary.
///
/// The one letter the two routes read apart is `\u{131}`: CaseFolding.txt maps
/// it only under the Turkic status, so `str.casefold` leaves it alone, while
/// upper-casing reaches `I` and lower-casing it reaches `i`. That would make
/// `SK\u{131}LL.md` primary here and not primary there, so this refuses the
/// letter rather than letting it spell the name.
fn component_name_is(path: &Path, expected: &str) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        !name.contains('\u{131}') && name.to_uppercase().to_lowercase() == expected
    })
}

/// Whether the text walks upward out of the directories it names.
///
/// Nothing that discovers a skill document writes a `..` into its path, so a
/// path carrying one is not a document this reader was handed. It matters
/// because the safe-root check below reads the `skills` root rather than the
/// document: `skills/x/../../../elsewhere/SKILL.md` keeps a root inside the
/// safe roots while the file it resolves to sits outside the skills tree.
fn walks_upward(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

/// The nearest ancestor directory named `skills`.
fn skills_root(document: &Path) -> Option<&Path> {
    document
        .ancestors()
        .skip(1)
        .find(|parent| component_name_is(parent, "skills"))
}

/// Whether the walk from the `skills` root down to the document crosses a
/// symlink, or leaves the root entirely.
fn crosses_a_symlink(document: &Path, root: &Path, process_directory: &Path) -> bool {
    let Ok(relative) = document.strip_prefix(root) else {
        return true;
    };
    let mut current = anchor(root, process_directory);
    if is_symlink(&current) {
        return true;
    }
    for part in relative.components() {
        current.push(part);
        if is_symlink(&current) {
            return true;
        }
    }
    false
}

/// Read one primary skill document's bounded evidence.
pub(crate) fn read_skill_document_evidence(
    document: &Path,
    process_directory: &Path,
    safe_roots: &[PathBuf],
) -> SkillDocumentEvidenceV1 {
    if !component_name_is(document, "skill.md") || walks_upward(document) {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    }
    let Some(root) = skills_root(document) else {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    };
    let Ok(relative) = document.strip_prefix(root) else {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    };
    // A document directly under the root has no skill directory of its own.
    if relative.components().count() < 2 {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    }
    let anchored = anchor(document, process_directory);
    if crosses_a_symlink(document, root, process_directory) || is_symlink(&anchored) {
        return stopped(SkillDocumentReadabilityV1::SymlinkRejected);
    }
    let Ok(resolved) = fs::canonicalize(&anchored) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let Ok(resolved_root) = fs::canonicalize(anchor(root, process_directory)) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let within_a_safe_root = safe_roots
        .iter()
        .filter_map(|root| fs::canonicalize(anchor(root, process_directory)).ok())
        .any(|root| resolved_root.starts_with(root));
    // The root is what the safe roots are checked against, so the document has
    // to be the one that root holds. Every symlink between the two is already
    // refused above, which leaves this an assertion for the paths that reach
    // here rather than a second resolution of its own.
    if !within_a_safe_root || !resolved.starts_with(&resolved_root) {
        return stopped(SkillDocumentReadabilityV1::OutsideSafeRoots);
    }
    read_resolved_document(&resolved)
}

/// Open the already-resolved path and read it under the ceiling.
///
/// The path holds no symlink of its own, so `O_NOFOLLOW` here only closes the
/// window between resolving and opening.
fn read_resolved_document(resolved: &Path) -> SkillDocumentEvidenceV1 {
    let Ok(mut file) = open_without_following(resolved) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let Ok(metadata) = file.metadata() else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let byte_length = metadata.len();
    if !metadata.is_file() {
        return stopped_with_size(SkillDocumentReadabilityV1::NotRegularFile, byte_length);
    }
    if byte_length > MAX_SKILL_DOCUMENT_BYTES as u64 {
        return stopped_with_size(SkillDocumentReadabilityV1::TooLarge, byte_length);
    }
    let mut content = Vec::new();
    if file
        .by_ref()
        .take(MAX_SKILL_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut content)
        .is_err()
    {
        // The size is already known, so a failed read reports it the way a
        // failed check below would.
        return stopped_with_size(SkillDocumentReadabilityV1::Unreadable, byte_length);
    }
    // A file that grew between the stat and the read is over the ceiling too.
    if content.len() > MAX_SKILL_DOCUMENT_BYTES {
        return stopped_with_size(SkillDocumentReadabilityV1::TooLarge, content.len() as u64);
    }
    let Ok(text) = std::str::from_utf8(&content) else {
        return stopped_with_size(SkillDocumentReadabilityV1::InvalidUtf8, byte_length);
    };
    let evidence = analyze_skill_document_text(text);
    SkillDocumentEvidenceV1 {
        readability_status: SkillDocumentReadabilityV1::Readable,
        byte_length: Some(byte_length),
        content_hash: Some(format!(
            "sha256:{}",
            guard_policy_snapshot::digest_bytes(&content)
        )),
        line_count: Some(evidence.line_count as u64),
        heading_count: Some(evidence.heading_count as u64),
        frontmatter_present: Some(evidence.frontmatter_present),
        documented_network_capability: evidence.documented_network_capability.map(str::to_owned),
    }
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    // Windows has no `O_NOFOLLOW`; the Python scanner fell back the same way,
    // and the path was already resolved and walked for symlinks above.
    fs::File::open(path)
}

#[cfg(test)]
#[path = "skill_document_evidence_tests.rs"]
mod tests;
