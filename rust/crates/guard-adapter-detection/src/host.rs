//! The narrow port a detection leaf holds: only the inventory, path and skill
//! operations a detector may touch. The runtime bridge supplies the shared
//! orchestration; the leaf never sees the request, the artifact vector or the
//! kind result.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::artifacts::Scope;

/// How a harness names its skill artifacts.
pub enum SkillNaming<'a> {
    /// Gemini and Antigravity: `skills/<dir>` is the id segment and the name,
    /// and a discovery issue is keyed by its id alone.
    Prefixed,
    /// Devin: `<dir>` is the id segment and the name, and a discovery issue is
    /// keyed by the skill root's label too.
    Bare { root_label: &'a str },
}

/// The directories one detection request names, already validated and
/// absolutized by the host.
pub struct DetectionRequest {
    pub home: PathBuf,
    pub workspace: Option<PathBuf>,
}

/// The inventory, path and skill operations a detection leaf may use.
///
/// Implementations keep the host I/O guarantees: `resolve` honors the request
/// working directory, `mark_found` preserves first-seen order, `scope_of` is
/// the `project`/`global` split, and `discover_skills` runs the shared skill
/// document discovery with its fail-closed warnings.
pub trait DetectionHost {
    /// Where `path` is on disk: a relative path reads from the request's
    /// working directory.
    fn resolve(&self, path: &Path) -> PathBuf;

    /// Python 3.12's `Path.is_dir` at `path`, read like `resolve`: `false`
    /// when nothing is there or it is not a directory, and a refusal for any
    /// other `stat` failure, so an unreadable directory never reads as empty.
    fn is_dir(&self, path: &Path) -> Result<bool, &'static str>;

    /// Marks `path` found, keeping first position among equal paths.
    fn mark_found(&mut self, path: &Path);

    /// Records one built artifact in discovery order.
    fn record(&mut self, artifact: Value);

    /// `project` below the workspace, else `global`.
    fn scope_of(&self, path: &Path) -> &'static str;

    /// The skill documents and discovery issues below `skill_root`; `label`
    /// names the harness in warnings and issue names.
    fn discover_skills(
        &mut self,
        scope: &Scope<'_>,
        label: &str,
        naming: &SkillNaming<'_>,
        skill_root: &Path,
        identity_root: &Path,
    ) -> Result<(), &'static str>;
}
