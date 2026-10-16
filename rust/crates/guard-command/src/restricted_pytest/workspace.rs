//! Native launch plan for `workspace-contained-v1`.
use super::workspace_linked::admissible_checkout;
use super::*;
use crate::pretool::generic::chain_literals::inert::temp_cd;
use crate::pretool::generic::{chain_literals, contained_publish, workspace_redirects};
use crate::pretool::workspace_git_config::{linked_git_dirs, workspace_write_denials};
use crate::pretool::workspace_git_environment::GitVariables;
use crate::pretool::{command_shape, Shape, WORKSPACE_PROFILE};
use crate::{parse_command, CommandModelRequestV1};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    text: String,
    workspace: PathBuf,
    cwd: PathBuf,
    platform: String,
    backend_executable: Option<PathBuf>,
    search_path: String,
    home: Option<PathBuf>,
    /// The caller's exported Git configuration variables, by value.
    git_environment: BTreeMap<String, String>,
    /// The receipt runs the checks contained and the trailing Git steps after
    /// them, outside the sandbox, once Guard proves those steps again.
    publish_suffix: bool,
}

fn invalid(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new(PYTEST_INVALID_COMMAND_REASON_CODE, message)
}

/// The canonical workspace for `cwd`, or `None` for a missing directory or a
/// filesystem, home, temporary or credential-directory root.
pub(crate) fn workspace_admissible(cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let resolved = cwd.canonicalize().ok()?;
    (resolved.is_dir() && !workspace_is_broad_or_sensitive_for_home(&resolved, home))
        .then_some(resolved)
}

/// The sandbox shape for the exact `text` about to run, or `None` when the
/// workspace sandbox cannot bound it. Literal-path redirects are classified
/// without them, chained `$NAME` uses as the literal assigned earlier in the
/// chain, and a `cd "$(mktemp -d)"` as the temporary stand-in; the raw text
/// still runs, so such a shape must run it whole, and the real `mktemp`
/// creates its directory under the sandbox's private `TMPDIR`.
pub(crate) fn exact_shape(text: &str, workspace: &Path) -> Option<Shape> {
    if let Some(projected) = temp_cd::project(text) {
        return exact_shape(&projected, workspace).filter(runs_whole);
    }
    match chain_literals::substitute(text) {
        Some(substituted) => literal_shape(&substituted, workspace).filter(runs_whole),
        None => literal_shape(text, workspace),
    }
}

fn runs_whole(shape: &Shape) -> bool {
    shape.bootstrap.is_none() && shape.prefix.is_none() && shape.remainder.is_none()
}

fn literal_shape(text: &str, workspace: &Path) -> Option<Shape> {
    match workspace_redirects::project(text) {
        Some(projected) => workspace_redirects::contained_shape(text, &projected, workspace),
        None => {
            let model = parse_command(&CommandModelRequestV1 {
                command: text.to_owned(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .ok()?;
            command_shape(&model, workspace, Some(text))
        }
    }
}

fn prepare(input: &Input) -> Result<Value, RestrictedPytestError> {
    let host = if cfg!(target_os = "macos") {
        input.platform == "darwin"
    } else {
        input.platform.starts_with("linux") && super::workspace_linux::available()
    };
    if !host {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "The workspace sandbox is not available on this host.",
        ));
    }
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    let workspace =
        workspace_admissible(&input.workspace, input.home.as_deref()).ok_or_else(|| {
            RestrictedPytestError::new(
                PYTEST_INVALID_WORKSPACE_REASON_CODE,
                "The workspace is not an admissible sandbox workspace.",
            )
        })?;
    if input.cwd.canonicalize().ok().as_deref() != Some(workspace.as_path()) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "The workspace sandbox runs only from the workspace root.",
        ));
    }
    // Re-derive the decision from the exact bytes about to run.
    let (contained, native_suffix) = if input.publish_suffix {
        let (checks, publish) = contained_publish::split(&input.text)
            .ok_or_else(|| invalid("The command does not split into checks and Git steps."))?;
        (checks, Some(publish))
    } else {
        (input.text.clone(), None)
    };
    let shape = exact_shape(&contained, &workspace)
        .filter(|shape| {
            native_suffix.is_none()
                || (shape.bootstrap.is_none()
                    && shape.prefix.is_none()
                    && shape.remainder.is_none())
        })
        .ok_or_else(|| invalid("The command is not eligible for the workspace sandbox."))?;
    let variables: GitVariables = input
        .git_environment
        .iter()
        .map(|(name, value)| (name.clone(), Some(value.clone())))
        .collect();
    let write_denials = workspace_write_denials(&workspace, input.home.as_deref(), &variables)
        .ok_or_else(|| invalid("The repository configuration is not eligible."))?;
    let text = shape.remainder.clone().unwrap_or(contained);
    let (exec_roots, sandbox_path) =
        workspace_exec_roots(&input.search_path, input.home.as_deref(), &workspace);
    // A linked worktree's index, HEAD and objects live in the main checkout's
    // `.git`, which the backend must also let the run write.
    // Its main checkout becomes readable too, so it must be admissible as a
    // workspace root would be.
    let linked_git = match linked_git_dirs(&workspace, input.home.as_deref()) {
        Some((common, _)) if !admissible_checkout(&common, input.home.as_deref()) => {
            return Err(invalid(
                "The linked worktree's main checkout is not an admissible sandbox root.",
            ));
        }
        linked => linked.map(|(common, admin)| json!({"common": common, "admin": admin})),
    };
    Ok(json!({
        "profile_version": WORKSPACE_PROFILE,
        "backend": backend,
        "backend_executable": backend_executable,
        "workspace": workspace,
        "cwd": workspace,
        "executable": "/bin/sh",
        "command": ["/bin/sh", "-c", text],
        "command_sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "allowed_executables": [],
        "read_only_roots": shape.read_files,
        "exec_roots": exec_roots,
        "write_denials": write_denials,
        "linked_git": linked_git,
        "sandbox_path": sandbox_path,
        "bootstrap_git": shape.bootstrap,
        "prefix_command": shape.prefix,
        "native_suffix": native_suffix,
        "denied_capabilities": [
            "network", "host-home-read", "host-secret-environment", "docker-socket",
            "workspace-credential-read", "git-execution-config-write", "privileged-operation"
        ],
    }))
}

/// The scripts outside `workspace` that `text` runs and the sandbox may read,
/// or `None` when the workspace sandbox cannot bound the command. A sink
/// compares a plan's read grants with these, so a plan can add no other file.
pub fn workspace_script_reads(text: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    exact_shape(text, workspace).map(|shape| shape.read_files)
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation != "prepare_workspace_contained" {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| invalid("Invalid restricted execution request."))
        .and_then(|input| prepare(&input));
    Some(match result {
        Ok(value) => json!({"value": value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}
