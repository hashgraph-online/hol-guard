//! What a fresh checkout holds at one path before anything else writes to it:
//! the proof behind `git worktree add <path> <ref> && ln -s <dir>
//! <path>/<sub>/<name>`, which shares a dependency directory with the new
//! checkout. Right after the add, the checkout holds exactly the tree of the
//! commit it checked out, since the worktree proof has already ruled out
//! hooks and filters that could write anything else.

use std::path::Path;
use std::time::Instant;

use super::{git_query_with_args, prepared_git_command};

/// Whether `parent` (`""` for the checkout root) is a directory the commit
/// tracks, reached through tracked directories only, and the commit tracks
/// no entry named `name` in it under any letter case. A tracked symbolic
/// link on the way is refused: `ln` would follow it out of the checkout. So
/// is a folder another entry of its tree names under a different case, which
/// a case-insensitive checkout merges with that entry.
/// `None` is doubt.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn tracked_directory_with_free_name(
    executable: &str,
    leading: &[String],
    commit: &str,
    parent: &str,
    name: &str,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let probe_deadline = Instant::now() + super::super::git_probe::PROBE_BUDGET;
    let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
    if Instant::now() >= deadline || name.is_empty() || Path::new(parent).is_absolute() {
        return None;
    }
    let (base, _binary, _cwd, _home) =
        prepared_git_command(executable, context, execution_environment)?;
    // Each level is listed by object name, so the probe's working directory
    // filters nothing out, and the walk sees every entry a case-insensitive
    // checkout would merge into one directory.
    let mut tree = format!("{commit}^{{tree}}");
    let components = parent.split('/').filter(|component| !component.is_empty());
    for component in components {
        if matches!(component, "." | "..") || !component.is_ascii() {
            return Some(false);
        }
        let entries = tree_entries(&base, leading, &tree, deadline)?;
        let mut colliding = entries
            .iter()
            .filter(|entry| may_collide(&entry.name, component));
        // One entry may take this name, spelled exactly, and it must be a
        // directory: a link or submodule there would lead out of the tree.
        match (colliding.next(), colliding.next()) {
            (Some(entry), None) if entry.name == component.as_bytes() && entry.mode == "040000" => {
                tree = entry.object.clone();
            }
            _ => return Some(false),
        }
    }
    if !name.is_ascii() {
        return Some(false);
    }
    let entries = tree_entries(&base, leading, &tree, deadline)?;
    Some(!entries.iter().any(|entry| may_collide(&entry.name, name)))
}

struct TreeEntry {
    mode: String,
    object: String,
    name: Vec<u8>,
}

/// Every entry of one tree object, as `ls-tree -z` prints it.
fn tree_entries(
    base: &std::process::Command,
    leading: &[String],
    tree: &str,
    deadline: Instant,
) -> Option<Vec<TreeEntry>> {
    let (status, listing) = git_query_with_args(
        base,
        leading,
        &["ls-tree", "-z", "--full-tree", tree],
        deadline,
        super::super::git_probe::LISTING_LIMIT,
    )?;
    if !status.success() {
        return None;
    }
    listing
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let tab = record.iter().position(|byte| *byte == b'\t')?;
            let header = std::str::from_utf8(&record[..tab]).ok()?;
            let mut fields = header.split(' ');
            let (Some(mode), Some(_kind), Some(object), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return None;
            };
            Some(TreeEntry {
                mode: mode.to_owned(),
                object: object.to_owned(),
                name: record[tab + 1..].to_vec(),
            })
        })
        .collect()
}

/// Whether a case-insensitive filesystem could store `entry` and the ASCII
/// `wanted` as one name. Unicode case folding and normalization can map a
/// non-ASCII name onto an ASCII one, so any such entry counts as colliding.
fn may_collide(entry: &[u8], wanted: &str) -> bool {
    !entry.is_ascii() || entry.eq_ignore_ascii_case(wanted.as_bytes())
}
