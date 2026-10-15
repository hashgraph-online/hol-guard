//! A `cd <sibling repository dir> && …` list. Agents step from one checkout
//! into a linked worktree or clone beside it this way. The execution sink
//! peels the same prefix and re-authorizes the remainder with that root as its
//! workspace (`contained_wrapper.py`), so the classifier holds the remainder
//! to the checks it would face from a session started in that root. The sink
//! resolves the root itself and runs nothing when it is gone, so `cd <root>;`
//! cannot fall back to the session directory and is peeled like `&&`.
use super::PathContext;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};

/// The sibling repository root that confines the run, and the commands to
/// check there: the rest after a `cd <root>` list, or `None` when the whole
/// text runs from the root as issued, `cd` included.
pub(super) fn sibling_run(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(PathBuf, Option<CanonicalCommandV1>)> {
    match sibling_list(model, context) {
        Some((root, rest)) => Some((root, Some(rest))),
        None => sibling_cd_root(model, context).map(|root| (root, None)),
    }
}

/// The sibling root and the commands after its `cd`, when the `cd` is
/// followed by `&&` or `;`, every later separator is `&&`, and the verified
/// target is a repository root outside the session's own workspace.
fn sibling_list(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(PathBuf, CanonicalCommandV1)> {
    let target = super::super::segment_proof::verified_cwd_list_context(model, context, true)?;
    let workspace = std::fs::canonicalize(context.cwd?).ok()?;
    let target = PathBuf::from(target);
    // The sink joins only an `&&` list after a sibling root; a pipe would
    // leave the `cd` to run under the session workspace's profile.
    if target.starts_with(&workspace)
        || model
            .segments
            .iter()
            .any(|segment| segment.pipeline_index != 0)
        || super::super::contained_wrapper::sibling_project_root(&target, context.home_dir?)
            .as_deref()
            != Some(target.as_path())
    {
        return None;
    }
    let mut rest = model.clone();
    rest.segments.remove(0);
    Some((target, rest))
}

/// The repository root for `cd <absolute dir in a sibling repository> &&
/// <one command>`, optionally ending in `2>&1` and `| tail -N`: a directory
/// below the root, such as a worktree package, or the root itself with an
/// output filter. The sink peels the same shape and, holding a workspace
/// receipt, runs the text as issued from that root, so the `cd` stays below
/// the workspace the sandbox confines. Every path the command names that
/// exists must resolve into the root or, for a linked worktree, its main
/// checkout: the trees the sandbox can read. A `node_modules` link into
/// another directory keeps its review instead of failing in the sandbox.
fn sibling_cd_root(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<PathBuf> {
    let [spelled] = model.segments.first()?.arguments.as_slice() else {
        return None;
    };
    if !Path::new(spelled).is_absolute() {
        return None;
    }
    let target = super::super::segment_proof::verified_cwd_compound_context(model, context)?;
    let target = PathBuf::from(target);
    let workspace = std::fs::canonicalize(context.cwd?).ok()?;
    if target.starts_with(&workspace) {
        return None;
    }
    let root = super::super::contained_wrapper::sibling_project_root(&target, context.home_dir?)?;
    let core = super::super::contained_wrapper::contained_core(model, context)?;
    let mut trees = vec![root.clone()];
    if let Some(checkout) = super::super::worktree_writes::linked_worktree_common_dir(&root)
        .and_then(|common| common.parent().map(Path::to_path_buf))
    {
        trees.push(checkout);
    }
    core.segments
        .iter()
        .all(|segment| names_readable(segment, &target, &trees))
        .then_some(root)
}

/// Whether every word of `segment` that names an existing path from
/// `directory` resolves below one of `trees`.
fn names_readable(segment: &CommandSegmentV1, directory: &Path, trees: &[PathBuf]) -> bool {
    segment
        .executable
        .iter()
        .chain(&segment.arguments)
        .all(|word| {
            let value = match word.split_once('=') {
                Some((option, value)) if option.starts_with('-') => value,
                _ => word.as_str(),
            };
            let path = directory.join(value);
            value.is_empty()
                || std::fs::symlink_metadata(&path).is_err()
                || std::fs::canonicalize(&path)
                    .is_ok_and(|resolved| trees.iter().any(|tree| resolved.starts_with(tree)))
        })
}
