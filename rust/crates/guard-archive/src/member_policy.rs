//! The per-member policy loop: a faithful port of
//! `offline_archive_worker._inspect_archive`. Every early return keeps its
//! original code and message; the fixed order of the checks is the reason
//! priority and is covered by the parity vectors.

use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;
use std::time::Instant;

use tar::Archive;

use crate::framing_guard::{FramingGuard, GuardReport, Verdict};
use crate::manifest::{install_script_risk, python_build_script_risk};
use crate::member_paths::{
    identity_key, member_kind, member_path_conflicts, name_ends_with_any, name_variants,
    normalized_link_target, replace_backslashes, unsafe_member_reason, MemberKind,
};
use crate::posix_path;
use crate::tar_policy::InspectStats;
use crate::{ArchiveCaps, ArchiveOutcome};

const NESTED_ARCHIVE_SUFFIXES: [&str; 9] = [
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip", ".whl",
];
const PYTHON_BUILD_MANIFESTS: [&str; 2] = ["setup.py", "pyproject.toml"];

/// Total bytes of member identity (paths and hard-link targets) retained for
/// the conflict and hard-link checks. Without it, a few thousand members with
/// path-sized names pin memory proportional to members times path length.
/// Real archives retain well under 1 MiB.
pub(crate) const MAX_RETAINED_IDENTITY_BYTES: u64 = 32 * 1024 * 1024;

fn guard_outcome(verdict: Verdict, actual: &Option<String>) -> ArchiveOutcome {
    match verdict {
        Verdict::MetadataTooLarge => ArchiveOutcome::blocked(
            "external_archive_member_size_limit",
            "External archive contains an oversized member.",
            actual.clone(),
        ),
        Verdict::SparseChainTooLong | Verdict::AmbiguousPax => ArchiveOutcome::blocked(
            "external_archive_unsupported_member",
            "External archive contains an unsupported member type.",
            actual.clone(),
        ),
        Verdict::Halted => ArchiveOutcome::halted(),
        Verdict::Timeout => ArchiveOutcome::timeout(actual.clone()),
    }
}

fn path_budget_exceeded(actual: &Option<String>) -> ArchiveOutcome {
    ArchiveOutcome::blocked(
        "external_archive_path_depth_limit",
        "External archive exceeded Guard's path-depth limit.",
        actual.clone(),
    )
}

pub(crate) fn scan_tar_members(
    reader: &mut dyn Read,
    compressed_size: u64,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    actual: &Option<String>,
) -> Result<InspectStats, ArchiveOutcome> {
    let report = Rc::new(GuardReport::default());
    // A per-member cap that is smaller than the metadata ceiling also bounds
    // long-name and PAX records.
    let guarded = FramingGuard::new(
        reader,
        caps.max_member_bytes,
        deadline,
        halt,
        Rc::clone(&report),
    );
    // A guard refusal reaches the library as a generic I/O error; the verdict
    // recorded by the guard is the real reason.
    let parse_failed = || {
        report.verdict().map_or_else(
            || {
                ArchiveOutcome::incomplete(
                    "external_archive_inspection_incomplete",
                    "External archive could not be parsed completely in offline inspection.",
                    actual.clone(),
                )
            },
            |verdict| guard_outcome(verdict, actual),
        )
    };
    let mut archive = Archive::new(guarded);
    let mut member_count: u64 = 0;
    let mut expanded_bytes: u64 = 0;
    let mut nested_archives: u64 = 0;
    let mut retained_bytes: u64 = 0;
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
        // Budget of the previous members, checked after all of their own
        // verdicts so it never reorders an existing reason.
        if retained_bytes > MAX_RETAINED_IDENTITY_BYTES {
            return Err(path_budget_exceeded(actual));
        }
        let mut entry = entry.map_err(|_| parse_failed())?;
        // Disagreement between the guard's framing and the library's is never
        // assumed away: the member is refused.
        if report.entry_header_pos() != Some(entry.raw_header_position()) {
            return Err(parse_failed());
        }
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
        let portable_path = identity_key(&normalized_name);
        if member_path_conflicts(&portable_path, kind, &seen_paths) {
            return Err(ArchiveOutcome::blocked(
                "external_archive_path_conflict",
                "External archive contains duplicate or conflicting member paths.",
                actual.clone(),
            ));
        }
        retained_bytes = retained_bytes.saturating_add(portable_path.len() as u64);
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
                let target = identity_key(&link_target);
                retained_bytes = retained_bytes.saturating_add(target.len() as u64);
                hardlink_targets.push(target);
            }
        }
        // `entry.size()` returns the *effective* member size: it honors a PAX
        // `size=` override, which `header().size()` (the raw octal field) does
        // not. Enforcement must match the bytes the iterator actually consumes,
        // otherwise a PAX size override inflates a member past the caps unseen.
        let member_size = entry.size();
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
        if name_ends_with_any(&normalized_name, &NESTED_ARCHIVE_SUFFIXES) {
            nested_archives += 1;
            if nested_archives > caps.max_nested_archives {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_nesting_limit",
                    "External archive exceeded Guard's nested-archive limit.",
                    actual.clone(),
                ));
            }
        }
        let variants = name_variants(posix_path::basename(&normalized_name));
        let recognized = |wanted: &[&str]| {
            variants
                .iter()
                .find(|name| wanted.contains(&name.as_str()))
                .cloned()
        };
        let is_package_manifest = recognized(&["package.json"]).is_some();
        let python_manifest = recognized(&PYTHON_BUILD_MANIFESTS);
        let is_node_gyp_manifest = recognized(&["binding.gyp"]).is_some();
        if (is_package_manifest || python_manifest.is_some() || is_node_gyp_manifest)
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
        if !is_package_manifest && python_manifest.is_none() {
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
                report.verdict().map_or_else(
                    || {
                        ArchiveOutcome::incomplete(
                            "external_archive_inspection_incomplete",
                            "External archive package manifest could not be read completely.",
                            actual.clone(),
                        )
                    },
                    |verdict| guard_outcome(verdict, actual),
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
        let risk = match &python_manifest {
            _ if is_package_manifest => install_script_risk(&manifest_payload),
            Some(name) => python_build_script_risk(name),
            None => None,
        };
        if let Some((code, message)) = risk {
            return Err(ArchiveOutcome::blocked(code, message, actual.clone()));
        }
    }
    // The iterator ends on a guard refusal as well as on a clean terminator.
    if let Some(verdict) = report.verdict() {
        return Err(guard_outcome(verdict, actual));
    }
    if retained_bytes > MAX_RETAINED_IDENTITY_BYTES {
        return Err(path_budget_exceeded(actual));
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
