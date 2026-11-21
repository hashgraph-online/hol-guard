//! The remotes gh resolves a base repository from, as Git itself lists them.
//!
//! gh reads `git remote -v` and the `remote.<name>.gh-resolved` keys, so the
//! probe asks Git the same questions in the environment the command
//! inherits: every configuration scope, include, legacy remote file and URL
//! rewrite counts, and an inherited `GIT_*` variable keeps the review.

use crate::pretool::git_session_probe::Probe;
use std::time::Instant;

pub(super) struct Remotes {
    /// The GitHub owner and repository every `origin` URL names, or `None`
    /// when there is no `origin`.
    pub(super) origin: Option<(String, String)>,
    /// No remote other than `origin`, and no `gh repo set-default` choice
    /// besides `origin` itself, so gh's base repository is origin or none.
    pub(super) origin_only: bool,
}

/// `None` when the probe cannot run or answer, or `origin` names anything
/// but one plain GitHub repository.
pub(super) fn resolve(
    context: crate::pretool::PathContext<'_>,
    deadline: Option<Instant>,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<Remotes> {
    let probe = Probe::new("git", &[], context, deadline, environment)?;
    let listing = probe.output(&["--no-pager", "remote", "-v"])?;
    let (origin, others) = listed(std::str::from_utf8(&listing).ok()?)?;
    let (config, _) = probe.config()?;
    let resolved_elsewhere = config.iter().any(|(key, values)| {
        key.strip_prefix("remote.")
            .and_then(|rest| rest.strip_suffix(".gh-resolved"))
            .is_some_and(|name| name != "origin" || values.iter().any(|value| value != "base"))
    });
    Some(Remotes {
        origin,
        origin_only: !others && !resolved_elsewhere,
    })
}

/// `<name>\t<url> (fetch|push)` lines: origin's one GitHub repository and
/// whether any other remote is listed.
pub(super) fn listed(listing: &str) -> Option<(Option<(String, String)>, bool)> {
    let mut origin: Option<(String, String)> = None;
    let mut others = false;
    for line in listing.lines() {
        let (name, rest) = line.split_once('\t')?;
        let url = rest
            .strip_suffix(" (fetch)")
            .or_else(|| rest.strip_suffix(" (push)"))?;
        if name != "origin" {
            others = true;
            continue;
        }
        let pair = super::github_repository(url)?;
        if origin.as_ref().is_some_and(|old| *old != pair) {
            return None;
        }
        origin = Some(pair);
    }
    Some((origin, others))
}
