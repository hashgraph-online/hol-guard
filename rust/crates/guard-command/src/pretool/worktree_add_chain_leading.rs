//! Conservative proof for a leading directory entry in a Git worktree chain.

use crate::CanonicalCommandV1;

/// The directory a leading `cd <dir> && ...` enters, when the whole chain
/// runs there.
///
/// An agent that keeps one checkout open writes the whole setup as
/// `cd <repository> && git worktree add ... && cd <checkout> && ...`. The
/// `cd` names a directory and stops: it reads nothing and creates nothing,
/// and `&&` means no step after it runs unless it succeeded. So the chain
/// runs in the directory it names, and every proof below reads the
/// repository that is actually there. A `;` or `||` would leave the rest
/// running in the directory the command started in, which no proof here
/// looked at, and a target the `cd` cannot be proved to reach leaves the
/// same doubt.
pub(super) fn leading_entry(
    model: &CanonicalCommandV1,
    context: super::super::super::PathContext<'_>,
) -> Option<String> {
    let first = model.segments.first()?;
    if first.executable.as_deref() != Some("cd")
        || first.pipeline_index != 0
        || !first.environment_names.is_empty()
        || !first.wrapper_chain.is_empty()
        || first.path_overridden
        || !super::super::super::directory_targets::drive_targets_quoted(first)
        || !super::super::super::directory_targets::home_targets_unquoted(first)
    {
        return None;
    }
    if super::super::separator_between(model, 0, 1)
        .as_deref()
        .map(str::trim)
        != Some("&&")
    {
        return None;
    }
    // A redirection reaches the parser as an argument, so a `cd` that also
    // writes a file is not the single-target step this proves.
    let [target] = first.arguments.as_slice() else {
        return None;
    };
    let resolved = super::super::super::directory_targets::verified_cwd_target(target, context)?;
    // An anchored alias can be trusted for a standalone cd, but not for a
    // worktree chain. The shell preserves logical PWD while Git resolves
    // relative worktree paths from the physical directory. A later cd ..
    // could therefore enter another checkout than the one Git created.
    // Relative operands already require an unaliased spelling in
    // verified_cwd_target; require the same for anchored Unix operands.
    #[cfg(unix)]
    {
        let tilde = super::super::super::directory_targets::home_variable::tilde_spelling(target);
        let spelled = tilde.as_deref().unwrap_or(target);
        let expanded = if spelled == "~" || spelled.starts_with("~/") {
            super::super::super::read_paths::expand_home_read_path(spelled, context.home_dir)?
        } else {
            spelled.to_owned()
        };
        let supplied = std::path::Path::new(&expanded);
        if supplied.is_absolute() && supplied != std::path::Path::new(&resolved) {
            return None;
        }
    }
    Some(resolved)
}

