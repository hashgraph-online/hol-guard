//! What the refresh proof reads outside the command itself: the transport
//! origin's URLs reach, the Git LFS configuration a checkout would smudge
//! through, the ref a merge target resolves to, and what a fast-forward that
//! fetches nothing could start.

use super::super::git_remote_config as config;
use super::super::git_session_probe::Probe;
use super::pull;

/// Git LFS takes its endpoint from `lfs.url`, `lfs.pushurl` or
/// `remote.<name>.lfsurl`, and how it authenticates there from
/// `lfs.<url>.access`, rather than from origin's URL.
pub(super) fn lfs_endpoint_overridden(effective: &config::GitConfig) -> bool {
    effective.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key == "lfs.url"
            || key == "lfs.pushurl"
            || (key.starts_with("remote.") && key.ends_with(".lfsurl"))
            || (key.starts_with("lfs.") && key.ends_with(".access"))
    })
}

/// No `.lfsconfig` names those keys from the work tree, the current commit
/// or the commit the fast-forward checks out. A probe that fails counts as
/// one being there.
pub(super) fn lfsconfig_absent(probe: &Probe, target: &str) -> bool {
    let Some(top) = probe.text(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    if std::fs::symlink_metadata(std::path::Path::new(&top).join(".lfsconfig")).is_ok() {
        return false;
    }
    ["HEAD", target].iter().all(|commit| {
        probe
            .output(&[
                "ls-tree",
                "--full-tree",
                "--name-only",
                "--end-of-options",
                commit,
                "--",
                ".lfsconfig",
            ])
            .is_some_and(|listed| listed.iter().all(u8::is_ascii_whitespace))
    })
}

/// Whether every remote `--all` walks is `origin`. Git builds a remote from
/// any `remote.<name>.<variable>` key and from each file under `remotes/` or
/// `branches/` in the common directory, which the configuration listing never
/// shows, so both have to be clear.
pub(super) fn every_remote_is_origin(effective: &config::GitConfig, probe: &Probe) -> bool {
    config::only_origin_remote(effective)
        && probe
            .text(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
            .and_then(|common| config::legacy_remotes_absent(std::path::Path::new(&common)))
            == Some(true)
}

/// The network half of the proof: every origin URL reaches GitHub, no
/// configuration routes the transport through a program, credential helpers
/// are trusted, and no `pager.fetch` names a program for the fetch's output.
pub(super) fn transport_proven(
    effective: &config::GitConfig,
    repository: &config::GitConfig,
    probe: &Probe,
) -> bool {
    let urls = effective
        .get("remote.origin.url")
        .map_or(&[][..], Vec::as_slice);
    !urls.is_empty()
        && urls.iter().all(|url| {
            config::rewritten_remote_url(effective, url.trim())
                .is_some_and(|url| config::safe_github_remote_url(&url))
        })
        && !config::fetch_config_routes_execution(effective)
        && probe.credential_helpers_trusted(&config::credential_helpers(effective))
        && !config::config_weakens_transport(effective)
        && !config::repository_config_routes_transport(repository)
        && !pull::pager_enabled(effective, "fetch")
}

/// Whether Git resolves the merge target to origin's remote-tracking ref,
/// rather than a ref such as a tag or local branch spelled `origin/<branch>`
/// that Git would pick first.
pub(super) fn tracks_origin(probe: &Probe, target: &str) -> bool {
    let Some(full) = probe.text(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--symbolic-full-name",
        target,
    ]) else {
        return false;
    };
    if target.starts_with("origin/") {
        full == format!("refs/remotes/{target}")
    } else {
        full.starts_with("refs/remotes/origin/")
    }
}

/// The work tree half of the pull proof, for a fast-forward merge that
/// fetches nothing: the checkout, ref update and automatic maintenance start
/// no program. A partial clone would fetch the blobs it checks out from a
/// remote this proof has not read, submodules carry their own hooks, and a
/// virtual file system names a program Git runs on every index read.
pub(super) fn fast_forward_inert(
    effective: &config::GitConfig,
    repository: &config::GitConfig,
    shape: pull::Pull,
    probe: &Probe,
) -> bool {
    !effective.iter().any(|(key, values)| {
        matches!(
            key.as_str(),
            "extensions.partialclone" | "core.virtualfilesystem"
        ) || key.starts_with("submodule.")
            || (key.starts_with("remote.")
                && key.ends_with(".promisor")
                && values.iter().any(|value| !pull::disabled(value)))
    }) && probe.hooks_inert(["reference-transaction", "pre-auto-gc"])
        && pull::pull_inert(effective, repository, shape, probe)
}
