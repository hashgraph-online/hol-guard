//! Where `cd` and `pushd` may move a contained command: a literal directory
//! below the workspace, or a fresh directory under the run's private
//! temporary directory, which only this run can write. Operands after either
//! move are still judged as workspace paths, so a `cd` that fails leaves
//! nothing the checks did not see.

use crate::pretool::generic::chain_literals::inert::temp_cd;
use crate::CanonicalCommandV1;
use std::path::Path;

/// A literal directory at or below the workspace, with no parent step.
fn below(target: &str, workspace: &Path) -> bool {
    let path = Path::new(target);
    !target.is_empty()
        && !target.starts_with(['~', '-'])
        && !target.contains('$')
        && path
            .components()
            .all(|component| !matches!(component, std::path::Component::ParentDir))
        && (path.is_relative() || path.starts_with(workspace))
}

/// Whether `target`, the only operand of a `cd` or `pushd`, is a directory
/// the sandbox bounds. `temp_fixed` says nothing rebinds `TMPDIR`, so the
/// stand-in for `"$(mktemp -d)"` is a directory `mktemp` creates under the
/// run's private temporary directory.
pub(super) fn bounded(target: &str, workspace: &Path, temp_fixed: bool) -> bool {
    below(target, workspace) || (temp_fixed && temp_cd::private_directory(target))
}

/// Whether every temporary stand-in in the command is the only operand of a
/// `cd` or `pushd`. Anywhere else it would pass the path checks as a missing
/// absolute path while the real command names the private directory.
pub(super) fn stand_ins_only_entered(model: &CanonicalCommandV1) -> bool {
    let mentions = temp_cd::mentions(&model.normalized_text);
    mentions == 0
        || mentions
            == model
                .segments
                .iter()
                .filter(|segment| {
                    segment.executable.as_deref().is_some_and(|executable| {
                        matches!(
                            crate::pretool::executable_basename(executable),
                            "cd" | "pushd"
                        )
                    }) && matches!(
                        segment.arguments.as_slice(),
                        [target] if temp_cd::private_directory(target)
                    )
                })
                .count()
}

#[cfg(test)]
#[path = "workspace_contained_cd_tests.rs"]
mod tests;
