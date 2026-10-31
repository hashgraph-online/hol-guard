//! The workspace sandbox plan, admitted only when it runs exactly the
//! authorized command.

use sha2::{Digest, Sha256};

use crate::contained_workspace_grant_plan::ExpectedGrant;

use super::*;

/// A plan `prepare_workspace_contained` returned and the checks admitted.
pub(super) struct Plan {
    /// Checked on every host, because the plan is one contract; read only by
    /// the Seatbelt profile this host builds from it.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(super) profile_version: String,
    pub(super) capabilities: Value,
    pub(super) argv: Vec<String>,
    pub(super) prefix: Option<String>,
    /// The Git steps a publish chain runs on the host once the checks pass.
    pub(super) suffix: Option<String>,
    pub(super) bootstrap: Option<Value>,
    pub(super) backend_executable: String,
    pub(super) sandbox_path: String,
    pub(super) linked_git: Value,
    pub(super) exec_roots: Value,
    pub(super) read_only_roots: Value,
    pub(super) write_denials: Value,
}

/// With `publish`, the plan runs only the checks before the Git steps it
/// names, and neither bootstraps nor prefixes them.
pub(super) fn validated_plan(
    plan: Value,
    command: &str,
    workspace: &str,
    publish: bool,
    grant: Option<&ExpectedGrant>,
) -> Outcome<Plan> {
    let Value::Object(mut plan) = plan else {
        return Err(Failure::invalid(INVALID_PLAN));
    };
    let mut keys: Vec<&str> = plan.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = PLAN_FIELDS;
    expected.sort_unstable();
    if keys != expected {
        return Err(Failure::invalid(INVALID_PLAN));
    }
    // A base plan without a decided grant; with one, a plan widened by it.
    let scripts = crate::contained_workspace_grant_plan::grant_script_roots(&plan, grant)
        .ok_or_else(|| Failure::invalid(INVALID_PLAN))?;
    let mismatch = || Failure::invalid(PLAN_MISMATCH);
    let suffix = match &plan["native_suffix"] {
        Value::Null if !publish => None,
        Value::String(suffix) if publish => Some(suffix.clone()),
        _ => return Err(mismatch()),
    };
    let command = match &suffix {
        Some(suffix) if plan["prefix_command"].is_null() && plan["bootstrap_git"].is_null() => {
            super::split::checks(command, suffix).ok_or_else(mismatch)?
        }
        Some(_) => return Err(mismatch()),
        None => command,
    };
    let argv: Vec<String> = match &plan["command"] {
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or_else(mismatch)?,
        _ => return Err(mismatch()),
    };
    if argv.len() != 3 || argv[0] != "/bin/sh" || argv[1] != "-c" {
        return Err(mismatch());
    }
    let script = argv[2].as_str();
    let bootstrap = match plan.remove("bootstrap_git") {
        Some(Value::Null) | None => None,
        Some(value) => Some(value),
    };
    let prefix = match &plan["prefix_command"] {
        Value::Null => None,
        Value::String(prefix)
            if bootstrap.is_some()
                && command.starts_with(prefix.as_str())
                && prefix.chars().count() + script.chars().count() < command.chars().count() =>
        {
            Some(prefix.clone())
        }
        _ => return Err(mismatch()),
    };
    let script_bound = if bootstrap.is_none() {
        script == command
    } else {
        command.ends_with(script)
    };
    let backend = plan["backend"].as_str();
    if HOST_BACKEND.is_none()
        || backend != HOST_BACKEND
        || plan["command_sha256"].as_str() != Some(hex::encode(Sha256::digest(script)).as_str())
        || !script_bound
        || plan["workspace"]
            .as_str()
            .is_none_or(|text| py_normal(text) != workspace)
        || plan["allowed_executables"] != json!([])
        || !read_grants_match(&scripts, command, workspace)
        || !(plan["linked_git"].is_null() || linked_git(&plan["linked_git"]))
    {
        return Err(mismatch());
    }
    let text = |value: &Value| value.as_str().map(str::to_owned);
    Ok(Plan {
        profile_version: text(&plan["profile_version"])
            .ok_or_else(|| Failure::invalid(INVALID_PLAN))?,
        capabilities: plan["capabilities"].clone(),
        prefix,
        suffix,
        bootstrap,
        backend_executable: text(&plan["backend_executable"])
            .ok_or_else(|| Failure::invalid(INVALID_PLAN))?,
        sandbox_path: text(&plan["sandbox_path"]).ok_or_else(|| Failure::invalid(INVALID_PLAN))?,
        linked_git: plan["linked_git"].clone(),
        exec_roots: plan["exec_roots"].clone(),
        read_only_roots: plan["read_only_roots"].clone(),
        write_denials: plan["write_denials"].clone(),
        argv,
    })
}

/// The plan grants read access to exactly the scripts outside the workspace
/// that the authorized command launches, and to nothing else.
fn read_grants_match(granted: &Value, command: &str, workspace: &str) -> bool {
    *granted == json!([])
        || guard_command::restricted_pytest::workspace_script_reads(command, Path::new(workspace))
            .is_some_and(|expected| *granted == json!(expected))
}

/// A linked worktree's shared `.git` and admin entry, as the plan names them.
pub(super) fn linked_git(value: &Value) -> bool {
    value.as_object().is_some_and(|entries| {
        entries.len() == 2
            && ["common", "admin"].iter().all(|name| {
                entries
                    .get(*name)
                    .and_then(Value::as_str)
                    .is_some_and(|path| path.starts_with('/'))
            })
    })
}

pub(super) fn plan_paths(value: &Value) -> Outcome<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(Failure::invalid(INVALID_PLAN));
    };
    items
        .iter()
        .map(|item| item.as_str().map(|text| wire_path(Path::new(text))))
        .collect::<Option<_>>()
        .ok_or_else(|| Failure::invalid(INVALID_PLAN))
}

/// The sibling repository the call runs in: the one a plain command's
/// absolute script or tool lies in, or the one a leading `cd` enters below
/// its root. The edge roots that call's sandbox there, so the sink plans and
/// runs the whole text, `cd` included, from that root, as Guard's own sink
/// does.
pub(super) fn sibling_root(
    payload: &Map<String, Value>,
    workspace: &str,
    home: &Path,
) -> Option<PathBuf> {
    let command = payload.get("tool_input")?.get("command")?.as_str()?;
    let home = home.to_str()?;
    let plan =
        guard_command::pretool::contained_wrapper_plan(command, workspace, None, Some(home), None);
    let root = match plan.anchored_sibling_root {
        Some(root) => root,
        None => entered_sibling_root(&plan.plan?.directory, workspace, home)?,
    };
    root.is_dir().then_some(root)
}

/// The sibling repository a call's leading `cd` enters below its root, which
/// the native sink runs the call from (`sibling_root`).
pub(crate) fn entered_sibling(command: &str, workspace: &str, home: &str) -> Option<PathBuf> {
    let plan =
        guard_command::pretool::contained_wrapper_plan(command, workspace, None, Some(home), None);
    if plan.anchored_sibling_root.is_some() {
        return None;
    }
    entered_sibling_root(&plan.plan?.directory, workspace, home)
}

/// The sibling repository a peeled `cd` enters, when the directory lies
/// below that repository's root. A `cd` to the root itself is authorized
/// again for the command after it, which only Guard's sink does, so it has
/// none here, as does a directory inside the workspace or in no repository.
fn entered_sibling_root(directory: &Path, workspace: &str, home: &str) -> Option<PathBuf> {
    let directory = std::fs::canonicalize(directory).ok()?;
    if directory.starts_with(std::fs::canonicalize(workspace).ok()?) {
        return None;
    }
    let query = directory.to_str()?;
    let root = guard_command::pretool::contained_wrapper_plan(
        "",
        workspace,
        None,
        Some(home),
        Some(query),
    )
    .project_root?;
    let root = std::fs::canonicalize(root).ok()?;
    (root != directory && directory.starts_with(&root)).then_some(root)
}

#[cfg(test)]
#[path = "contained_workspace_sink_sibling_tests.rs"]
mod sibling_tests;
