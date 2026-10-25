//! A copy into a directory created earlier in the same chain:
//! `mkdir -p src/lib/notes && cp /tmp/checkout/README.md src/lib/notes/`.
//!
//! Each `cp` segment is still proven on its own against the files on disk, so
//! the only thing an earlier `mkdir` can change is whether a destination is a
//! directory. With several sources or a trailing slash, cp never writes the
//! destination path itself, and the proof already checked `<dir>/<name>`. A
//! single source without a trailing slash is only accepted when every `mkdir`
//! target in the chain is the destination's parent or one of its ancestors,
//! byte for byte. Matching names instead would miss case-insensitive or
//! normalization-insensitive volumes, where `mkdir -p src/Sub` makes
//! `src/sub` a directory and the copy lands on a name the proof never saw.
//! Every directory such a chain creates sits strictly above the destination,
//! so none of them can be the destination itself. `mkdir` creates real
//! directories, never links, so the resolved location of every later target
//! stays the one the proof saw. Only plain peers may share the chain: nothing
//! changes directory, renames, links or removes files.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};

/// Two or more segments, at least one `mkdir`, and every other segment a
/// plain chain peer. Git may share a chain without a copy:
/// `git fetch origin main && mkdir -p ~/notes`. Each Git segment still needs
/// its own proof, and `mkdir` cannot create the hidden `.git` metadata a Git
/// command reads. The `mkdir` targets are screened against the files on disk
/// before the chain runs, so only Git commands that never write the work tree
/// may join: a `git pull`, `git checkout` or `git worktree add` could check
/// out a tracked link such as `notes -> ~/.ssh` that a later `mkdir -p
/// notes/keys` would follow. Copies keep the plain peers.
pub(in crate::pretool) fn mkdir_chain(model: &CanonicalCommandV1) -> bool {
    let named = |name: &str| {
        model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some(name))
    };
    model.segments.len() > 1
        && (super::plain_chain(model, &["mkdir"])
            || (!named("cp")
                && super::plain_chain(model, &["mkdir", "git"])
                && model.segments.iter().all(leaves_work_tree)))
        && named("mkdir")
}

/// A chain whose writers only bring a path into being. `mkdir` creates a
/// directory and `touch` creates an empty file or bumps a timestamp; neither
/// changes directory, renames, links or removes anything. Every segment is
/// still proven on its own against the files on disk, so the only thing an
/// earlier segment can settle for a later one is whether a parent directory
/// exists, and `mkdir` makes real directories rather than links. Plain peers
/// may read alongside them: `mkdir -p build && touch build/.keep`,
/// `touch src/new.ts && ls src`.
pub(in crate::pretool) fn creation_chain(model: &CanonicalCommandV1) -> bool {
    model.segments.len() > 1 && super::plain_chain(model, &["mkdir", "touch"])
}

/// Git subcommands that read the repository or update only refs and
/// metadata, never files in the work tree.
const WORK_TREE_READERS: &[&str] = &[
    "blame",
    "branch",
    "cat-file",
    "describe",
    "diff",
    "fetch",
    "for-each-ref",
    "grep",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge-base",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-ref",
    "status",
];

/// Git global options that take the next token as their value.
const GIT_VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
];

/// A non-Git segment, or a Git segment whose subcommand cannot write the
/// work tree.
fn leaves_work_tree(segment: &CommandSegmentV1) -> bool {
    segment.executable.as_deref() != Some("git")
        || git_subcommand(segment).is_some_and(|name| WORK_TREE_READERS.contains(&name))
}

/// The subcommand of a Git segment, after any global options and their values.
pub(super) fn git_subcommand(segment: &CommandSegmentV1) -> Option<&str> {
    let mut index = 0;
    while let Some(argument) = segment.arguments.get(index) {
        if GIT_VALUE_OPTIONS.contains(&argument.as_str()) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return Some(argument.as_str());
        }
    }
    None
}

/// A `cp` segment in a [`mkdir_chain`] whose destination no `mkdir` in the
/// chain can turn into a directory the proof did not see, however the volume
/// compares names.
pub(super) fn copies_beside_mkdir(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> bool {
    mkdir_chain(model) && destination_settled(model, segment, context)
}

fn destination_settled(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> bool {
    let operands = match segment.arguments.as_slice() {
        [separator, rest @ ..] if separator == "--" => rest,
        operands => operands,
    };
    // Flagged copies (recursive, archive, link-making) stay out of the chain.
    if operands.iter().any(|operand| operand.starts_with('-')) {
        return false;
    }
    let Some((destination, sources)) = operands.split_last() else {
        return false;
    };
    if sources.len() > 1 || destination.ends_with('/') {
        return true;
    }
    let Some(destination) = resolved(destination, context) else {
        return false;
    };
    let Some(parent) = destination.parent() else {
        return false;
    };
    model
        .segments
        .iter()
        .filter(|peer| peer.executable.as_deref() == Some("mkdir"))
        .flat_map(|peer| peer.arguments.iter())
        .filter(|argument| !argument.starts_with('-'))
        .all(|target| resolved(target, context).is_some_and(|target| parent.starts_with(target)))
}

/// The absolute location a path names once missing parts are created: the
/// canonical deepest existing ancestor plus the missing parts. `..` parts and
/// dangling links are refused, so every missing part is a plain name.
fn resolved(value: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
    if value.split(['/', '\\']).any(|part| part == "..") {
        return None;
    }
    let expanded = super::super::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let path = Path::new(&expanded);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let cwd = context.cwd?;
        let cwd = super::super::read_paths::expand_home_read_path(cwd, context.home_dir)
            .unwrap_or_else(|| cwd.to_owned());
        Path::new(&cwd).join(path)
    };
    let mut missing = Vec::new();
    let mut existing = absolute.as_path();
    while existing.symlink_metadata().is_err() {
        let name = existing.file_name()?;
        missing.push(name.to_owned());
        existing = existing.parent()?;
    }
    let mut canonical = existing.canonicalize().ok()?;
    for name in missing.iter().rev() {
        canonical.push(name);
    }
    Some(canonical)
}

#[cfg(test)]
mod tests {
    fn model(command: &str) -> crate::CanonicalCommandV1 {
        crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "test".to_owned(),
        })
        .unwrap()
    }

    /// Only writers that bring a path into being, beside peers that read,
    /// share a creation chain. A segment that changes directory, renames,
    /// links or removes can put a different file under the name a later
    /// `touch` was screened against, so it keeps the chain out.
    #[test]
    fn only_creating_writers_and_plain_peers_share_a_creation_chain() {
        for (command, shared) in [
            ("mkdir -p build && touch build/.keep", true),
            ("mkdir -p build; touch build/.keep", true),
            ("touch a.txt && touch b.txt", true),
            ("ls && touch a.txt", true),
            ("touch build/.keep && ls build", true),
            // One segment is proven on its own, never as a chain.
            ("touch a.txt", false),
            ("ln -s /etc link && touch link/hosts", false),
            ("cd /etc && touch hosts", false),
            ("mv notes.md a.txt && touch notes.md", false),
            ("rm -rf build && touch build", false),
            ("git checkout main && touch a.txt", false),
        ] {
            assert_eq!(super::creation_chain(&model(command)), shared, "{command}");
        }
    }
}
