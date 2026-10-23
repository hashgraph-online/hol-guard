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
pub(super) use directory_copies::{creation_chain, mkdir_chain};

use crate::CanonicalCommandV1;
use std::path::{Component, Path, PathBuf};

/// Segments that print, filter or copy a file. None changes directory,
/// renames a file or creates a link.
const CHAIN_PEERS: &[&str] = &[
    "cat", "cp", "cut", "diff", "echo", "grep", "head", "jq", "ls", "nl", "printf", "rg", "sort",
    "tail", "tr", "true", "uniq", "wc",
];

/// Scratch editors that may also share a chain. Each segment is still proven
/// on its own: `awk` only with a print-only program, and `sed` only as a read
/// or as an inert in-place edit of one file the proof names. Neither changes
/// directory or creates a link, and an in-place edit replaces only the file
/// it was given, so no segment can swap another leaf for a symlink.
const EDIT_PEERS: &[&str] = &["awk", "sed"];

/// Every segment is a plain peer spelled by name, with no wrapper, no
/// environment assignment and no path override.
pub(super) fn peers_only(model: &CanonicalCommandV1) -> bool {
    plain_chain(model, EDIT_PEERS)
}

/// Git subcommands that only read objects and history. None writes a file
/// outside the repository, changes directory, renames a file or creates a
/// link, so one may share a chain with a temporary file it fills or reads:
/// `git -C ../app show <rev>:src/a.ts > /tmp/a.ts && wc -l /tmp/a.ts`. A
/// working-tree command (`status`, `checkout`, `pull`) or a `--output` flag
/// stays out, and each Git segment still needs its own proof.
const GIT_OBJECT_READERS: &[&str] = &[
    "cat-file",
    "diff",
    "log",
    "ls-files",
    "ls-tree",
    "merge-base",
    "rev-list",
    "rev-parse",
    "show",
    "show-ref",
];

/// Plain peers beside Git object reads. This is the guard for a temporary file
/// a chain writes or reads; [`peers_only`] stays the guard for copies.
pub(super) fn temporary_peers(model: &CanonicalCommandV1) -> bool {
    peers_only(model)
        || (plain_chain(model, &["git"])
            && model.segments.iter().all(|segment| {
                segment.executable.as_deref() != Some("git")
                    || (directory_copies::git_subcommand(segment)
                        .is_some_and(|name| GIT_OBJECT_READERS.contains(&name))
                        && !segment
                            .arguments
                            .iter()
                            .any(|argument| argument.starts_with("--output")))
            }))
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
/// at that path first, so it is only proven beside plain peers. `mkdir` makes
/// directories and never links, so it may share such a chain too.
pub(super) fn absent_reads_bounded(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    model.segments.len() == 1
        || temporary_peers(model)
        || plain_chain(model, &["awk", "mkdir", "sed"])
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

/// The scratch directories that `mkdir` segments of a chain of plain peers
/// create, spelled as the command spells them. Each is a new child of a
/// private temporary directory that passes the same screens as a new
/// temporary file, so `cp` may place files directly inside it although its
/// parent does not exist when the hook runs. `mkdir` makes real directories
/// only, and the chain has no segment that links, renames or changes
/// directory, so the proven parent is the one the copy lands in.
pub(super) fn created_scratch_directories(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Vec<PathBuf> {
    if model.segments.len() < 2 || !plain_chain(model, &["mkdir"]) {
        return Vec::new();
    }
    model
        .segments
        .iter()
        .filter(|segment| segment.executable.as_deref() == Some("mkdir"))
        .flat_map(|segment| segment.arguments.iter())
        .filter(|argument| !argument.starts_with('-'))
        .filter(|argument| absent_temporary_read_target(argument, context.home_dir, context.cwd))
        .filter(|argument| private_scratch_parent(argument, context.home_dir))
        .map(PathBuf::from)
        .collect()
}

/// The parent of a directory the chain creates is an existing directory the
/// user owns that no one else can write, and not the shared `/tmp` or
/// `/var/tmp` root. Another user could create the same name in a shared root
/// before the chain runs, and `mkdir -p` would accept it silently, so a copy
/// into it could follow a link the other user planted.
#[cfg(unix)]
fn private_scratch_parent(argument: &str, home_dir: Option<&str>) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Some(owner) = home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|metadata| metadata.uid())
    else {
        return false;
    };
    let Some(parent) = Path::new(argument)
        .parent()
        .and_then(|parent| std::fs::canonicalize(parent).ok())
    else {
        return false;
    };
    let shared = ["/tmp", "/var/tmp"]
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| root == parent);
    !shared
        && parent.metadata().is_ok_and(|metadata| {
            metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
        })
}

#[cfg(not(unix))]
fn private_scratch_parent(_argument: &str, _home_dir: Option<&str>) -> bool {
    false
}
