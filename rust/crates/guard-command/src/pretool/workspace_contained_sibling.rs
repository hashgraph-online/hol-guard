//! A `cd <sibling repository root> && …` list. Agents step from one checkout
//! into a linked worktree or clone beside it this way. The execution sink
//! peels the same prefix and re-authorizes the remainder with that root as its
//! workspace (`contained_wrapper.py`), so the classifier holds the remainder
//! to the checks it would face from a session started in that root. The sink
//! resolves the root itself and runs nothing when it is gone, so `cd <root>;`
//! cannot fall back to the session directory and is peeled like `&&`.
use super::PathContext;
use crate::CanonicalCommandV1;
use std::path::PathBuf;

/// The sibling root and the commands after its `cd`, when the `cd` is
/// followed by `&&` or `;`, every later separator is `&&`, and the verified
/// target is a repository root outside the session's own workspace.
pub(super) fn sibling_list(
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
