//! Chain-local temporary files. Agents stage scratch output in a private
//! temporary file and read, extend or copy it later in the same command:
//! `head -60 src/a.ts > /tmp/p.ts; printf 'x' >> /tmp/p.ts; cp /tmp/p.ts src/b.ts`.
//!
//! The file usually does not exist when the hook runs, so its path is proven
//! instead: the parent is a temporary root or a private temporary directory,
//! and the leaf is absent or a regular single-link file the user owns. Only
//! peers that cannot change directory, rename files or create links may share
//! such a chain, so no earlier segment can swap the leaf for a symlink before
//! a later segment opens it.

#[path = "chain_directory_copies.rs"]
mod directory_copies;
pub(super) use directory_copies::mkdir_chain;

use crate::CanonicalCommandV1;
use std::path::{Component, Path};

/// Segments that print, filter or copy a file. None changes directory,
/// renames a file or creates a link.
const CHAIN_PEERS: &[&str] = &[
    "cat", "cp", "cut", "diff", "echo", "grep", "head", "jq", "ls", "nl", "printf", "rg", "sort",
    "tail", "tr", "true", "uniq", "wc",
];

/// Every segment is a plain peer spelled by name, with no wrapper, no
/// environment assignment and no path override.
pub(super) fn peers_only(model: &CanonicalCommandV1) -> bool {
    plain_chain(model, &[])
}

/// Like [`peers_only`], but `extra` names may also appear in the chain.
pub(super) fn plain_chain(model: &CanonicalCommandV1, extra: &[&str]) -> bool {
    model.confidence == "exact"
        && model.uncertainty_reason.is_none()
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && model.segments.iter().all(|segment| {
            segment.wrapper_chain.is_empty()
                && segment.environment_names.is_empty()
                && !segment.path_overridden
                && segment.executable.as_deref().is_some_and(|executable| {
                    CHAIN_PEERS.contains(&executable) || extra.contains(&executable)
                })
        })
}

/// An absolute temporary path that is absent or a regular single-link file
/// the user owns. Hidden and credential-shaped names never qualify.
pub(super) fn temporary_file_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let path = Path::new(value);
    // `Path::components` drops interior `.` parts, so screen the text too.
    path.is_absolute()
        && !value.starts_with('~')
        && !value.split(['/', '\\']).any(|part| part == ".")
        && !path.components().any(|component| match component {
            Component::Normal(part) => part.to_string_lossy().starts_with('.'),
            Component::ParentDir | Component::CurDir => true,
            _ => false,
        })
        && !super::sensitive_read_path_argument(value)
        && super::safe_writes::bounded_native_temporary_write_target(value, home_dir, cwd)
}

/// A temporary file that does not exist yet. Reading it only reports a
/// missing file. A dangling symlink is not absent.
pub(super) fn absent_temporary_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    Path::new(value).is_absolute()
        && std::fs::symlink_metadata(value)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        && temporary_file_target(value, home_dir, cwd)
}

/// A read of an absent temporary file relies on the chain not creating a link
/// at that path first, so it is only proven beside plain peers.
pub(super) fn absent_reads_bounded(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    model.segments.len() == 1
        || peers_only(model)
        || !model.segments.iter().any(|segment| {
            segment.arguments.iter().any(|argument| {
                absent_temporary_read_target(argument, context.home_dir, context.cwd)
            })
        })
}

/// `cp` shares a chain in two shapes, both only beside plain peers: a staged
/// temporary file copied to a relative workspace path, or a readable file
/// copied into a chain-local temporary file that later peers print or compare.
/// Reading such a copy discloses nothing a read of the source would not, and
/// `safe_copy_arguments` still holds the source to the ordinary read proof.
/// The destination still passes every check a single `cp` gets. A third
/// shape, a copy into a directory an earlier `mkdir` creates, is described in
/// `chain_directory_copies.rs`.
pub(super) fn copy_segments_allowed(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if model.segments.len() == 1 || directory_copies::copies_beside_mkdir(model, segment, context) {
        return true;
    }
    let (source, destination) = match segment.arguments.as_slice() {
        [source, destination] => (source, destination),
        [separator, source, destination] if separator == "--" => (source, destination),
        _ => return false,
    };
    let into_workspace = !destination.starts_with(['/', '\\', '~', '-'])
        && !destination.split(['/', '\\']).any(|part| part == "..")
        && temporary_file_target(source, context.home_dir, context.cwd);
    let into_temporary = !source.starts_with('-')
        && temporary_file_target(destination, context.home_dir, context.cwd);
    peers_only(model) && (into_workspace || into_temporary)
}
