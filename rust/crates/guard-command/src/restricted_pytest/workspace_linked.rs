//! A linked worktree's shared repository in `workspace-contained-v1`.
//!
//! Git keeps a linked worktree's index, `HEAD` and reflog in its admin entry
//! under the main checkout's `.git/worktrees`, and its objects and refs in
//! that shared `.git`. A run in the worktree may write exactly those, as a
//! run in the main checkout may write its own, and may read the main
//! checkout, which Git and links in the worktree reach. The shared
//! configuration, hooks, `info`, `objects/info`, other worktrees' entries and
//! the admin entry's own configuration and links stay unwritable.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct LinkedGit {
    pub(super) common: PathBuf,
    pub(super) admin: PathBuf,
}

/// Admin-entry files that commits, checkouts, resets and merges rewrite, the
/// locks Git takes to update or delete each ref among them (a commit deletes
/// `AUTO_MERGE` through its lock), and the reflog directory a first commit
/// creates.
const ADMIN_FILES: &[&str] = &[
    "index",
    "index.lock",
    "HEAD",
    "HEAD.lock",
    "ORIG_HEAD",
    "ORIG_HEAD.lock",
    "COMMIT_EDITMSG",
    "AUTO_MERGE",
    "AUTO_MERGE.lock",
    "MERGE_HEAD",
    "MERGE_HEAD.lock",
    "MERGE_MSG",
    "MERGE_MODE",
    "logs",
    "logs/HEAD",
];
/// Shared directories that hold objects, refs and reflogs.
const SHARED_TREES: &[&str] = &["objects", "refs", "logs"];
const SHARED_FILES: &[&str] = &["packed-refs", "packed-refs.lock"];

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid workspace sandbox request.",
    )
}

/// Whether a run may read and execute the main checkout holding the shared
/// directory `common`: it must not be a root no workspace may be, such as
/// `/`, a temporary root, a home directory or one of its credential folders.
pub(super) fn admissible_checkout(common: &Path, home: Option<&Path>) -> bool {
    common
        .parent()
        .is_some_and(|checkout| !workspace_is_broad_or_sensitive_for_home(checkout, home))
}

impl LinkedGit {
    /// `self` when it names a checkout's `.git` and an admin entry directly
    /// under its `worktrees`, and neither the shared directory nor
    /// `workspace` holds the other.
    pub(super) fn checked(&self, workspace: &Path) -> Result<&Self, RestrictedPytestError> {
        let entry = self.admin.file_name().and_then(OsStr::to_str);
        let valid = self.common.is_absolute()
            && workspace.is_absolute()
            && self.common.file_name() == Some(OsStr::new(".git"))
            && self.admin.parent() == Some(self.common.join("worktrees").as_path())
            && entry.is_some_and(|name| name != "." && name != "..")
            && !workspace.starts_with(&self.common)
            && !self.common.starts_with(workspace);
        valid.then_some(self).ok_or_else(invalid)
    }

    /// [`Self::checked`], when also each of `layers` is an absolute path
    /// apart from the workspace, the main checkout, each of `others` and each
    /// other.
    pub(super) fn with_layers(
        &self,
        workspace: &Path,
        layers: &[&Path],
        others: &[&Path],
    ) -> Result<&Self, RestrictedPytestError> {
        let apart =
            |left: &Path, right: &Path| !left.starts_with(right) && !right.starts_with(left);
        let fixed = [workspace, self.checkout()];
        let overlaps = layers.iter().enumerate().any(|(index, layer)| {
            !layer.is_absolute()
                || fixed.iter().chain(others).any(|other| !apart(layer, other))
                || layers[index + 1..].iter().any(|other| !apart(layer, other))
        });
        if overlaps {
            return Err(invalid());
        }
        self.checked(workspace)
    }

    /// The main checkout, which the run may read.
    pub(super) fn checkout(&self) -> &Path {
        self.common.parent().unwrap_or(&self.common)
    }

    /// The shared directories the run may write below. Each stays in place.
    pub(super) fn shared_trees(&self) -> Vec<PathBuf> {
        SHARED_TREES
            .iter()
            .map(|name| self.common.join(name))
            .collect()
    }

    /// The single files the run may write: the packed refs and the admin
    /// entry's index, `HEAD`s, reflog and merge state.
    pub(super) fn files(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        (
            SHARED_FILES
                .iter()
                .map(|name| self.common.join(name))
                .collect(),
            ADMIN_FILES
                .iter()
                .map(|name| self.admin.join(name))
                .collect(),
        )
    }

    /// Shared paths no change may touch even below a shared tree: a bare
    /// repository planted beside a ref store, `objects/info` and credentials.
    pub(super) fn denial_patterns(&self) -> Result<Vec<String>, RestrictedPytestError> {
        let mut sources = vec![
            super::profiles::workspace_profile::ref_store_repository_pattern(self.checkout())?,
            format!(
                "^{}/objects/info(/.*)?$",
                regex::escape(&self.common.to_string_lossy())
            ),
        ];
        sources.extend(super::credentials::patterns());
        Ok(sources)
    }

    /// The `HEAD`s the run may write despite the bare-repository rule.
    pub(super) fn heads(&self) -> Vec<PathBuf> {
        vec![self.admin.join("HEAD"), self.admin.join("logs/HEAD")]
    }

    /// Every path a Linux run's changes to the shared directory may touch,
    /// as an exact-case regex: below a shared tree, the packed refs, or one
    /// of the admin entry's files.
    pub(super) fn overlay_pattern(&self) -> Result<String, RestrictedPytestError> {
        let escaped = |names: &[&str]| {
            names
                .iter()
                .map(|name| regex::escape(name))
                .collect::<Vec<_>>()
                .join("|")
        };
        let entry = self
            .admin
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(invalid)?;
        Ok(format!(
            "^{}/(({})/.+|{}|worktrees/{}/({}))$",
            regex::escape(&self.common.to_string_lossy()),
            escaped(SHARED_TREES),
            escaped(SHARED_FILES),
            regex::escape(entry),
            escaped(ADMIN_FILES),
        ))
    }
}

#[cfg(test)]
#[path = "workspace_linked_tests.rs"]
mod tests;
