//! The remote branch `git worktree add <path> <name>` starts from when no
//! local branch or other ref is called `<name>`.
//!
//! Git then looks for a remote-tracking branch of that name in exactly one
//! remote and, finding one, creates `<name>` tracking it. That is how an agent
//! checks out a branch it has fetched but never checked out, so the proof
//! follows Git to that ref instead of reviewing the command.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use super::ConfigFacts;

/// What Git does with a `<name>` that names no local branch or other ref.
pub(super) enum Tracking {
    /// Creates `<name>` tracking this `refs/remotes/<remote>/<name>`.
    Unique(String),
    /// Stops with "invalid reference" before writing anything.
    Missing,
    /// Something this proof does not model: several remotes have the branch,
    /// or a remote maps its branches somewhere else.
    Unproven,
}

/// The ref Git would start the new branch from, or `None` when the probe
/// cannot tell.
///
/// Only the standard fetch refspec is followed: any other mapping, or a remote
/// defined outside the config in `remotes/` or `branches/`, could point Git at
/// a ref this proof does not read, so the command stays reviewed.
pub(super) fn resolve(
    base: &Command,
    leading: &[String],
    name: &str,
    facts: &ConfigFacts,
    common_dir: &Path,
    deadline: Instant,
) -> Option<Tracking> {
    if !super::super::worktree_add::valid_branch_name(name)
        || !super::super::git_remote_config::legacy_remotes_absent(common_dir)?
    {
        return Some(Tracking::Unproven);
    }
    let mut remotes: Vec<&str> = Vec::new();
    for (remote, refspec) in &facts.remote_fetch {
        if !standard_refspec(remote, refspec) {
            return Some(Tracking::Unproven);
        }
        if !remotes.contains(&remote.as_str()) {
            remotes.push(remote);
        }
    }
    let mut found = None;
    for remote in remotes {
        let tracking = format!("refs/remotes/{remote}/{name}");
        let (status, output) = super::git_query_with_args(
            base,
            leading,
            &["show-ref", "--verify", "--quiet", &tracking],
            deadline,
            super::WORKTREE_PROBE_LIMIT,
        )?;
        if status.success() {
            if found.is_some() {
                return Some(Tracking::Unproven);
            }
            found = Some(tracking);
        } else if status.code() != Some(1) || !output.is_empty() {
            return None;
        }
    }
    Some(found.map_or(Tracking::Missing, Tracking::Unique))
}

/// `git remote add` writes `+refs/heads/*:refs/remotes/<remote>/*`.
fn standard_refspec(remote: &str, refspec: &str) -> bool {
    !remote.is_empty()
        && super::super::worktree_add::valid_branch_name(remote)
        && refspec.strip_prefix('+').unwrap_or(refspec)
            == format!("refs/heads/*:refs/remotes/{remote}/*")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refspec_git_remote_add_writes_is_followed() {
        assert!(standard_refspec(
            "origin",
            "+refs/heads/*:refs/remotes/origin/*"
        ));
        assert!(standard_refspec(
            "upstream",
            "refs/heads/*:refs/remotes/upstream/*"
        ));
    }

    #[test]
    fn any_other_mapping_is_not_followed() {
        for (remote, refspec) in [
            ("origin", "+refs/heads/*:refs/remotes/upstream/*"),
            ("origin", "+refs/heads/main:refs/remotes/origin/main"),
            ("origin", "+refs/heads/*:refs/heads/*"),
            ("origin", "^refs/heads/secret"),
            ("origin", ""),
            ("", "+refs/heads/*:refs/remotes//*"),
        ] {
            assert!(!standard_refspec(remote, refspec), "{remote} {refspec}");
        }
    }
}
