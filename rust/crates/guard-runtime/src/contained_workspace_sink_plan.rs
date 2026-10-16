//! The workspace sandbox plan, admitted only when it runs exactly the
//! authorized command.

use sha2::{Digest, Sha256};

use super::*;

/// A plan `prepare_workspace_contained` returned and the checks admitted.
pub(super) struct Plan {
    pub(super) argv: Vec<String>,
    pub(super) prefix: Option<String>,
    pub(super) bootstrap: Option<Value>,
    pub(super) backend_executable: String,
    pub(super) sandbox_path: String,
    pub(super) linked_git: Value,
    pub(super) exec_roots: Value,
    pub(super) read_only_roots: Value,
    pub(super) write_denials: Value,
}

pub(super) fn validated_plan(plan: Value, command: &str, workspace: &str) -> Outcome<Plan> {
    let Value::Object(mut plan) = plan else {
        return Err(Failure::invalid(INVALID_PLAN));
    };
    let mut keys: Vec<&str> = plan.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = PLAN_FIELDS;
    expected.sort_unstable();
    if keys != expected || plan["profile_version"] != json!(WORKSPACE_PROFILE) {
        return Err(Failure::invalid(INVALID_PLAN));
    }
    if !plan["native_suffix"].is_null() {
        return Err(Failure::invalid(PLAN_MISMATCH));
    }
    let mismatch = || Failure::invalid(PLAN_MISMATCH);
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
        || !read_grants_match(&plan["read_only_roots"], command, workspace)
        || !(plan["linked_git"].is_null() || linked_git(&plan["linked_git"]))
    {
        return Err(mismatch());
    }
    let text = |value: &Value| value.as_str().map(str::to_owned);
    Ok(Plan {
        prefix,
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
