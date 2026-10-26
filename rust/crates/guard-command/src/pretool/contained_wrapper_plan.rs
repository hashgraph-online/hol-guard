//! The execution sink's peel, decided once, in the grammar the classifier uses.
//!
//! The sink used to recover the core command, its directory and its output
//! handling by lexing the text a second time in Python. That copy carried its
//! own sibling-repository rule, which could not read a Windows owner SID, so
//! it peeled checkouts the classifier had refused and handed the sandbox a
//! core no receipt covered. The grammar lives in `sink_peel` now, beside the
//! classifier's own, and both read the same sibling-repository rule.
use super::{contained_wrapper, workspace_contained, PathContext};
use crate::{parse_command, CommandModelRequestV1};
use std::path::PathBuf;

/// The sink refused the shape and runs the command whole in its sandbox, as
/// the Python peel's `ValueError` did.
pub const CONTAINED_WRAPPER_PLAN_UNSUPPORTED: &str = "native_contained_wrapper_plan_unsupported";

/// How the sink handles the core's output.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedOutput {
    /// `head`, `tail`, `pipe` or `all`.
    pub kind: &'static str,
    /// The line count a `head`/`tail` stage keeps; zero for the other kinds.
    pub count: u32,
    /// The core ended in `2>&1`, so the sink merges stderr into stdout.
    pub merge_stderr: bool,
    /// The label a trailing `; echo "label$?"` prints before the status.
    pub status_label: Option<String>,
    /// Each stage of a `pipe` chain, as its program followed by arguments.
    pub stages: Vec<Vec<String>>,
}

/// The core the sink runs, and where.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedWrapperCore {
    pub core: String,
    pub directory: PathBuf,
    pub output: Option<ContainedOutput>,
}

/// Everything the sink asks about one command.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContainedWrapperPlan {
    /// The peel, or `None` when nothing is wrapped.
    pub plan: Option<ContainedWrapperCore>,
    /// Set when the shape is wrapped but unsupported.
    pub refusal: Option<&'static str>,
    /// The sibling repository an absolute script runs from, when no wrapper
    /// was peeled.
    pub anchored_sibling_root: Option<PathBuf>,
    /// The sibling repository holding the directory the caller asked about,
    /// independently of the command.
    pub project_root: Option<PathBuf>,
}

/// Peel `command` the way the sink runs it.
///
/// `workspace` is the sandbox root; `cwd` the directory the command was issued
/// from. The environment proofs are set here because the sink peels only a
/// command the classifier already admitted under the real environment, and the
/// Python peel this replaces consulted no environment at all.
pub fn contained_wrapper_plan(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
    project_root_query: Option<&str>,
) -> ContainedWrapperPlan {
    let project_root = project_root_query.and_then(|directory| {
        contained_wrapper::sibling_project_root(std::path::Path::new(directory), home_dir?)
    });
    ContainedWrapperPlan {
        project_root,
        ..wrapper_plan(
            command,
            workspace,
            cwd,
            home_dir,
            SINK_PEELS_RELATIVE_INSIDE,
        )
    }
}

/// Only a host with no workspace sandbox peels an `&&`-joined relative `cd`
/// that stays inside the workspace; elsewhere the sandbox runs that text
/// whole. The resident answers for the host it runs on, which is the sink's.
const SINK_PEELS_RELATIVE_INSIDE: bool = cfg!(windows);

/// The peel alone, without the standalone directory question.
fn wrapper_plan(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
    peels_relative_inside: bool,
) -> ContainedWrapperPlan {
    match super::sink_peel::peel(command, workspace, cwd, home_dir, peels_relative_inside) {
        Ok(Some(core)) => ContainedWrapperPlan {
            plan: Some(core),
            ..ContainedWrapperPlan::default()
        },
        Ok(None) => ContainedWrapperPlan {
            anchored_sibling_root: anchored_root(command, workspace, cwd, home_dir),
            ..ContainedWrapperPlan::default()
        },
        Err(_) => ContainedWrapperPlan {
            refusal: Some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED),
            anchored_sibling_root: anchored_root(command, workspace, cwd, home_dir),
            ..ContainedWrapperPlan::default()
        },
    }
}

/// The sibling repository one plain command's absolute script or tool names,
/// which roots the sandbox there as a `cd <root> &&` prefix would.
fn anchored_root(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
) -> Option<PathBuf> {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .ok()?;
    let context = PathContext {
        home_dir,
        cwd: cwd.or(Some(workspace)),
        cdpath_unset: true,
        shell_home_matches: true,
        ..PathContext::default()
    };
    match workspace_contained::sibling::sibling_run(&model, context)? {
        (root, None) => Some(root),
        (_, Some(_)) => None,
    }
}

#[cfg(test)]
#[path = "contained_wrapper_plan_tests.rs"]
mod tests;
