//! The configuration a local write needs quiet, and the `stash show` flags
//! that keep a named diff driver from running.

use super::super::git_remote_config::GitConfig;
use crate::CanonicalCommandV1;

/// `external_off` and `textconv_off` are set only when every write in the
/// command is a `stash show` that keeps that driver from running.
pub(super) fn inert_with(
    effective: &GitConfig,
    repository: &GitConfig,
    external_off: bool,
    textconv_off: bool,
) -> bool {
    !super::super::git_remote_ops::pull::repository_lfs_program(repository)
        && !effective.iter().any(|(key, values)| {
            let enabled = values
                .iter()
                .any(|value| !super::super::git_remote_ops::pull::disabled(value));
            (key.starts_with("filter.")
                && (!super::super::git_remote_ops::pull::standard_lfs(key, values)
                    || repository.contains_key(key)))
                || key.starts_with("hook.")
                || key == "core.worktree"
                || key == "core.virtualfilesystem"
                || (key == "diff.external" && !external_off)
                || key == "extensions.partialclone"
                || (key.starts_with("diff.") && key.ends_with(".command") && !external_off)
                || (key.starts_with("diff.") && key.ends_with(".textconv") && !textconv_off)
                || (key.starts_with("trailer.")
                    && (key.ends_with(".command") || key.ends_with(".cmd")))
                || (key.starts_with("remote.") && key.ends_with(".promisor") && enabled)
                || (matches!(key.as_str(), "core.fsmonitor" | "submodule.recurse") && enabled)
        })
}

/// Whether every local write is a `stash show` whose flags keep the named
/// diff driver from running.
pub(super) fn diff_drivers_disarmed(
    model: &CanonicalCommandV1,
    writes: &[(usize, &'static [&'static str])],
    stashed: &[usize],
) -> (bool, bool) {
    if stashed.is_empty() || writes.iter().any(|(index, _)| !stashed.contains(index)) {
        return (false, false);
    }
    stashed
        .iter()
        .try_fold((true, true), |acc, index| {
            super::forms::show_diff_drivers_disarmed(&model.segments[*index])
                .map(|(external, textconv)| (acc.0 && external, acc.1 && textconv))
        })
        .unwrap_or((false, false))
}
