//! Archive admission, streaming hash, decompression preflight, and the
//! per-member policy loop — a faithful port of `offline_archive_worker.py`
//! and `offline_archive_policy.py`. Result codes and messages are part of the
//! caller contract and must not drift.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use flate2::read::MultiGzDecoder;
use guard_secure_fs::{open_immutable_blob, SecureReadError};
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};

use crate::manifest::{install_script_risk, python_build_script_risk};
use crate::posix_path;
use crate::{ArchiveCaps, ArchiveOutcome};

const HASH_CHUNK: usize = 64 * 1024;
const NESTED_ARCHIVE_SUFFIXES: [&str; 9] = [
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip", ".whl",
];
const PYTHON_BUILD_MANIFESTS: [&str; 2] = ["setup.py", "pyproject.toml"];

pub(crate) struct InspectStats {
    pub sha256: String,
    pub members: u64,
    pub expanded_bytes: u64,
}

enum HashFailure {
    Timeout,
    Halted,
    Io,
    OverLimit,
}

/// Stream a SHA-256 over `source`, honoring the byte cap, deadline, and halt
/// predicate exactly like `_hash_stream`.
fn hash_stream(
    source: &mut impl Read,
    max_bytes: u64,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> Result<(String, u64), HashFailure> {
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    let mut buffer = vec![0u8; HASH_CHUNK];
    loop {
        if halt() {
            return Err(HashFailure::Halted);
        }
        if Instant::now() > deadline {
            return Err(HashFailure::Timeout);
        }
        let count = source.read(&mut buffer).map_err(|_| HashFailure::Io)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > max_bytes {
            return Err(HashFailure::OverLimit);
        }
        digest.update(&buffer[..count]);
    }
    Ok((hex::encode(digest.finalize()), size))
}

pub(crate) fn inspect(
    path: &Path,
    expected_sha256: &str,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> Result<InspectStats, ArchiveOutcome> {
    let blob = open_immutable_blob(path).map_err(|error| match error {
        SecureReadError::SymlinkInPath
        | SecureReadError::NotRegularFile
        | SecureReadError::HardLinkedFile
        | SecureReadError::MutableLeaf => ArchiveOutcome::blocked(
            "external_archive_blob_rejected",
            "External archive blob is not a regular immutable file.",
            None,
        ),
        _ => ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be opened for offline inspection.",
            None,
        ),
    })?;
    if blob.identity.size > caps.max_archive_bytes {
        return Err(ArchiveOutcome::blocked(
            "external_archive_download_size_limit",
            "External archive exceeded Guard's inspection size limit.",
            None,
        ));
    }
    let mut file = blob.file;
    let (actual_sha256, actual_size) =
        match hash_stream(&mut file, caps.max_archive_bytes, deadline, halt) {
            Ok(pair) => pair,
            Err(HashFailure::Timeout) => return Err(ArchiveOutcome::timeout(None)),
            Err(HashFailure::Halted) => return Err(ArchiveOutcome::halted()),
            Err(_) => {
                return Err(ArchiveOutcome::incomplete(
                    "external_archive_inspection_incomplete",
                    "External archive could not be read completely for offline inspection.",
                    None,
                ))
            }
        };
    if actual_size != blob.identity.size || actual_sha256 != expected_sha256 {
        return Err(ArchiveOutcome::blocked(
            "external_archive_digest_mismatch",
            "External archive changed between download and offline inspection.",
            Some(actual_sha256),
        ));
    }
    let actual = Some(actual_sha256.clone());
    let mut stats = scan_bound_stream(&mut file, actual_size, caps, deadline, halt, &actual)?;

    // Post-inspection rehash: the launched artifact must be the inspected
    // bytes, so the digest is verified once more on the same descriptor.
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            actual.clone(),
        )
    })?;
    match hash_stream(&mut file, caps.max_archive_bytes, deadline, halt) {
        Ok((final_sha256, final_size)) => {
            if final_size != actual_size || final_sha256 != expected_sha256 {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_digest_mismatch",
                    "External archive changed during offline inspection.",
                    Some(final_sha256),
                ));
            }
        }
        Err(HashFailure::Timeout) => return Err(ArchiveOutcome::timeout(actual.clone())),
        Err(HashFailure::Halted) => return Err(ArchiveOutcome::halted()),
        Err(_) => {
            return Err(ArchiveOutcome::incomplete(
                "external_archive_inspection_incomplete",
                "External archive could not be parsed completely in offline inspection.",
                actual.clone(),
            ))
        }
    }
    stats.sha256 = actual_sha256;
    Ok(stats)
}

/// Preflight the decompressed stream, then run the member policy loop on the
/// same descriptor, mirroring the worker's seek-and-reparse structure.
fn scan_bound_stream(
    file: &mut std::fs::File,
    compressed_size: u64,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    actual: &Option<String>,
) -> Result<InspectStats, ArchiveOutcome> {
    let gzipped = preflight_expanded_stream(file, compressed_size, caps, deadline, halt, actual)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            actual.clone(),
        )
    })?;
    if gzipped {
        let reader = MultiGzDecoder::new(&mut *file);
        scan_tar_members(reader, compressed_size, caps, deadline, halt, actual)
    } else {
        scan_tar_members(&mut *file, compressed_size, caps, deadline, halt, actual)
    }
}

/// `_preflight_expanded_tar_stream`: reject unsupported compression and bound
/// the decompressed stream before tar parsing touches it. Returns whether the
/// stream is gzip-compressed so the parse can wrap it identically.
fn preflight_expanded_stream(
    file: &mut std::fs::File,
    compressed_size: u64,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    actual: &Option<String>,
) -> Result<bool, ArchiveOutcome> {
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            actual.clone(),
        )
    })?;
    let mut magic = [0u8; 6];
    let mut magic_len = 0;
    while magic_len < magic.len() {
        let count = file.read(&mut magic[magic_len..]).map_err(|_| {
            ArchiveOutcome::incomplete(
                "external_archive_inspection_incomplete",
                "External archive could not be parsed completely in offline inspection.",
                actual.clone(),
            )
        })?;
        if count == 0 {
            break;
        }
        magic_len += count;
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            actual.clone(),
        )
    })?;
    let magic = &magic[..magic_len];
    if magic.starts_with(b"BZh") || magic.starts_with(b"\xfd7zXZ\x00") {
        return Err(ArchiveOutcome::blocked(
            "external_archive_unsupported_format",
            "External archive uses an unsupported compression format.",
            actual.clone(),
        ));
    }
    let gzipped = magic.starts_with(b"\x1f\x8b");
    let mut expanded: u64 = 0;
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut drain = |reader: &mut dyn Read| -> Result<(), ArchiveOutcome> {
        loop {
            if halt() {
                return Err(ArchiveOutcome::halted());
            }
            if Instant::now() > deadline {
                return Err(ArchiveOutcome::timeout(actual.clone()));
            }
            let count = reader.read(&mut buffer).map_err(|_| {
                ArchiveOutcome::incomplete(
                    "external_archive_inspection_incomplete",
                    "External archive could not be parsed completely in offline inspection.",
                    actual.clone(),
                )
            })?;
            if count == 0 {
                return Ok(());
            }
            expanded += count as u64;
            if expanded > caps.max_expanded_bytes {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_expanded_size_limit",
                    "External archive exceeded Guard's expanded-stream limit.",
                    actual.clone(),
                ));
            }
            if (expanded as f64) > (compressed_size.max(1) as f64) * caps.max_decompression_ratio {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_decompression_ratio_limit",
                    "External archive exceeded Guard's decompression-ratio limit.",
                    actual.clone(),
                ));
            }
        }
    };
    if gzipped {
        drain(&mut MultiGzDecoder::new(&mut *file))?;
    } else {
        drain(&mut *file)?;
    }
    Ok(gzipped)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    Directory,
    File,
    Symlink,
    Hardlink,
}

/// The per-member policy loop. Mirrors `offline_archive_worker._inspect_archive`
/// statement for statement; every early return keeps its original code and
/// message.
fn scan_tar_members(
    reader: impl Read,
    compressed_size: u64,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    actual: &Option<String>,
) -> Result<InspectStats, ArchiveOutcome> {
    let parse_failed = || {
        ArchiveOutcome::incomplete(
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            actual.clone(),
        )
    };
    let mut archive = Archive::new(reader);
    let mut member_count: u64 = 0;
    let mut expanded_bytes: u64 = 0;
    let mut nested_archives: u64 = 0;
    let mut seen_paths: HashMap<String, MemberKind> = HashMap::new();
    let mut hardlink_targets: Vec<String> = Vec::new();
    let entries = archive.entries().map_err(|_| parse_failed())?;
    for entry in entries {
        if halt() {
            return Err(ArchiveOutcome::halted());
        }
        if Instant::now() > deadline {
            return Err(ArchiveOutcome::timeout(actual.clone()));
        }
        let mut entry = entry.map_err(|_| parse_failed())?;
        member_count += 1;
        if member_count > caps.max_files {
            return Err(ArchiveOutcome::blocked(
                "tarball_file_count_limit",
                "External archive exceeded Guard's file-count limit.",
                actual.clone(),
            ));
        }
        let raw_name = replace_backslashes(&entry.path_bytes());
        let normalized_name = posix_path::normpath(&raw_name);
        if unsafe_member_reason(&entry, &raw_name, &normalized_name).is_some() {
            return Err(ArchiveOutcome::blocked(
                "tarball_zip_slip",
                "External archive contains unsafe paths, links, or special files.",
                actual.clone(),
            ));
        }
        if normalized_name.split(|b| *b == b'/').count() as u64 > caps.max_path_depth {
            return Err(ArchiveOutcome::blocked(
                "external_archive_path_depth_limit",
                "External archive exceeded Guard's path-depth limit.",
                actual.clone(),
            ));
        }
        let Some(kind) = member_kind(&entry) else {
            return Err(ArchiveOutcome::blocked(
                "external_archive_unsupported_member",
                "External archive contains an unsupported member type.",
                actual.clone(),
            ));
        };
        let portable_path =
            caseless::default_case_fold_str(&String::from_utf8_lossy(&normalized_name));
        if member_path_conflicts(&portable_path, kind, &seen_paths) {
            return Err(ArchiveOutcome::blocked(
                "external_archive_path_conflict",
                "External archive contains duplicate or conflicting member paths.",
                actual.clone(),
            ));
        }
        seen_paths.insert(portable_path, kind);
        if matches!(kind, MemberKind::Symlink | MemberKind::Hardlink) {
            let Some(link_target) = normalized_link_target(&entry, &normalized_name) else {
                return Err(ArchiveOutcome::blocked(
                    "tarball_zip_slip",
                    "External archive contains unsafe paths, links, or special files.",
                    actual.clone(),
                ));
            };
            if kind == MemberKind::Hardlink {
                hardlink_targets.push(caseless::default_case_fold_str(&String::from_utf8_lossy(
                    &link_target,
                )));
            }
        }
        let member_size = entry.header().size().map_err(|_| parse_failed())?;
        if member_size > caps.max_member_bytes {
            return Err(ArchiveOutcome::blocked(
                "external_archive_member_size_limit",
                "External archive contains an oversized member.",
                actual.clone(),
            ));
        }
        expanded_bytes = expanded_bytes.saturating_add(member_size);
        if expanded_bytes > caps.max_expanded_bytes {
            return Err(ArchiveOutcome::blocked(
                "external_archive_expanded_size_limit",
                "External archive exceeded Guard's expanded-size limit.",
                actual.clone(),
            ));
        }
        if (expanded_bytes as f64) > (compressed_size.max(1) as f64) * caps.max_decompression_ratio
        {
            return Err(ArchiveOutcome::blocked(
                "external_archive_decompression_ratio_limit",
                "External archive exceeded Guard's decompression-ratio limit.",
                actual.clone(),
            ));
        }
        let lowered_name = String::from_utf8_lossy(&normalized_name).to_lowercase();
        if NESTED_ARCHIVE_SUFFIXES
            .iter()
            .any(|suffix| lowered_name.ends_with(suffix))
        {
            nested_archives += 1;
            if nested_archives > caps.max_nested_archives {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_nesting_limit",
                    "External archive exceeded Guard's nested-archive limit.",
                    actual.clone(),
                ));
            }
        }
        let manifest_name =
            String::from_utf8_lossy(posix_path::basename(&normalized_name)).to_lowercase();
        let is_package_manifest = manifest_name == "package.json";
        let is_python_build_manifest = PYTHON_BUILD_MANIFESTS.contains(&manifest_name.as_str());
        let is_node_gyp_manifest = manifest_name == "binding.gyp";
        if (is_package_manifest || is_python_build_manifest || is_node_gyp_manifest)
            && kind != MemberKind::File
        {
            return Err(ArchiveOutcome::blocked(
                "external_archive_manifest_link",
                "External archive build manifest must be an independent regular file.",
                actual.clone(),
            ));
        }
        if is_node_gyp_manifest {
            return Err(ArchiveOutcome::blocked(
                "node_gyp_implicit_install_script",
                "External archive contains a native build manifest that npm may execute implicitly.",
                actual.clone(),
            ));
        }
        if !is_package_manifest && !is_python_build_manifest {
            continue;
        }
        if member_size > caps.max_package_json_bytes {
            return Err(ArchiveOutcome::blocked(
                "tarball_package_json_limit",
                "External archive package manifest exceeded Guard's scan limit.",
                actual.clone(),
            ));
        }
        // The member was proven to be a regular file above. The extra byte is
        // a bounded overflow probe; equality with the declared member size
        // also detects a truncated tar stream.
        let read_limit = member_size
            .saturating_add(1)
            .min(caps.max_package_json_bytes.saturating_add(1));
        let mut manifest_payload = Vec::new();
        entry
            .by_ref()
            .take(read_limit)
            .read_to_end(&mut manifest_payload)
            .map_err(|_| {
                ArchiveOutcome::incomplete(
                    "external_archive_inspection_incomplete",
                    "External archive package manifest could not be read completely.",
                    actual.clone(),
                )
            })?;
        if manifest_payload.len() as u64 != member_size
            || manifest_payload.len() as u64 > caps.max_package_json_bytes
        {
            return Err(ArchiveOutcome::incomplete(
                "external_archive_inspection_incomplete",
                "External archive package manifest could not be read completely.",
                actual.clone(),
            ));
        }
        let risk = if is_package_manifest {
            install_script_risk(&manifest_payload)
        } else {
            python_build_script_risk(&manifest_name)
        };
        if let Some((code, message)) = risk {
            return Err(ArchiveOutcome::blocked(code, message, actual.clone()));
        }
    }
    if hardlink_targets
        .iter()
        .any(|target| seen_paths.get(target.as_str()) != Some(&MemberKind::File))
    {
        return Err(ArchiveOutcome::blocked(
            "external_archive_unsafe_hardlink",
            "External archive contains a hard link without a regular in-archive target.",
            actual.clone(),
        ));
    }
    Ok(InspectStats {
        sha256: String::new(),
        members: member_count,
        expanded_bytes,
    })
}

fn replace_backslashes(bytes: &[u8]) -> Vec<u8> {
    if bytes.contains(&b'\\') {
        bytes
            .iter()
            .map(|b| if *b == b'\\' { b'/' } else { *b })
            .collect()
    } else {
        bytes.to_vec()
    }
}

/// `_unsafe_member_reason`: returns `Some` when the member is unsafe. The
/// caller collapses every reason to `tarball_zip_slip`, so only presence
/// matters.
fn unsafe_member_reason<R: Read>(
    entry: &tar::Entry<'_, R>,
    raw_name: &[u8],
    normalized_name: &[u8],
) -> Option<&'static str> {
    if posix_path::has_control_character(raw_name)
        || raw_name.starts_with(b"/")
        || normalized_name == b"."
        || normalized_name == b".."
        || normalized_name.starts_with(b"../")
    {
        return Some("unsafe_path");
    }
    let first_component = normalized_name
        .split(|b| *b == b'/')
        .next()
        .unwrap_or_default();
    if first_component.contains(&b':') {
        return Some("unsafe_path");
    }
    let entry_type = entry.header().entry_type();
    if matches!(
        entry_type,
        EntryType::Char | EntryType::Block | EntryType::Fifo
    ) {
        return Some("special_file");
    }
    if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
        let raw_target = entry
            .link_name_bytes()
            .map(|name| replace_backslashes(&name))
            .unwrap_or_default();
        if raw_target.is_empty() || raw_target.starts_with(b"/") {
            return Some("unsafe_link");
        }
        let resolved_target = if entry_type == EntryType::Link {
            posix_path::normpath(&raw_target)
        } else {
            let base = posix_path::dirname(normalized_name);
            posix_path::normpath(&posix_path::join(&base, &raw_target))
        };
        if resolved_target == b".." || resolved_target.starts_with(b"../") {
            return Some("unsafe_link");
        }
        if resolved_target
            .split(|b| *b == b'/')
            .next()
            .unwrap_or_default()
            .contains(&b':')
        {
            return Some("unsafe_link");
        }
    }
    None
}

fn member_kind<R: Read>(entry: &tar::Entry<'_, R>) -> Option<MemberKind> {
    match entry.header().entry_type() {
        EntryType::Directory => Some(MemberKind::Directory),
        EntryType::Regular => Some(MemberKind::File),
        EntryType::Symlink => Some(MemberKind::Symlink),
        EntryType::Link => Some(MemberKind::Hardlink),
        _ => None,
    }
}

/// `_member_path_conflicts` on the case-folded normalized path.
fn member_path_conflicts(name: &str, kind: MemberKind, seen: &HashMap<String, MemberKind>) -> bool {
    if seen.contains_key(name) {
        return true;
    }
    let components: Vec<&str> = name.split('/').collect();
    for index in 1..components.len() {
        let ancestor = components[..index].join("/");
        if let Some(ancestor_kind) = seen.get(ancestor.as_str()) {
            if *ancestor_kind != MemberKind::Directory {
                return true;
            }
        }
    }
    if kind != MemberKind::Directory {
        let descendant_prefix = format!("{name}/");
        if seen
            .keys()
            .any(|existing| existing.starts_with(descendant_prefix.as_str()))
        {
            return true;
        }
    }
    false
}

/// `_normalized_link_target`: resolved in-archive link target or `None` when
/// the target is unsafe.
fn normalized_link_target<R: Read>(
    entry: &tar::Entry<'_, R>,
    normalized_name: &[u8],
) -> Option<Vec<u8>> {
    let raw_target = entry
        .link_name_bytes()
        .map(|name| replace_backslashes(&name))
        .unwrap_or_default();
    if raw_target.is_empty()
        || posix_path::has_control_character(&raw_target)
        || raw_target.starts_with(b"/")
    {
        return None;
    }
    let resolved_target = if entry.header().entry_type() == EntryType::Link {
        posix_path::normpath(&raw_target)
    } else {
        let base = posix_path::dirname(normalized_name);
        posix_path::normpath(&posix_path::join(&base, &raw_target))
    };
    if resolved_target == b"." || resolved_target == b".." || resolved_target.starts_with(b"../") {
        return None;
    }
    if resolved_target
        .split(|b| *b == b'/')
        .next()
        .unwrap_or_default()
        .contains(&b':')
    {
        return None;
    }
    Some(resolved_target)
}
