//! Narrow read-only profiles for package-run CLI trust.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::{
    probe, py_path, segment_launch_identity, stable_identity_mapping, Abort,
    LocalToolEligibilityInput, Outcome,
};
use crate::cloud_audit_sync::urlsplit;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::command_model::CommandSegment;
use crate::command_tokens::executable_name;
use crate::sfrs_interpreter_trust::resolve_strict;
use crate::shell_secret_read_support::classify_request_secret_path;

const CONTEXT_DIRECTORY_VARIABLE: &str = "IMPECCABLE_CONTEXT_DIR";

static SELECTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Aimpeccable@(?:latest|\d+\.\d+\.\d+)\z").expect("selector pattern compiles")
});
static PINNED_SELECTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Aimpeccable@\d+\.\d+\.\d+\z").expect("pinned selector pattern compiles")
});

pub(super) struct PackageProfile {
    pub(super) identity_material: Value,
    pub(super) indefinite_allowed: bool,
}

pub(super) fn trusted_package_tool_profile(
    segment: &CommandSegment,
    input: &LocalToolEligibilityInput<'_>,
) -> Outcome<Option<PackageProfile>> {
    if !matches!(
        executable_name(segment.executable.as_deref()).as_deref(),
        Some("npx" | "bunx")
    ) {
        return Ok(None);
    }
    if segment.path_overridden || !segment.wrapper_chain.is_empty() {
        return Ok(None);
    }
    let identity = segment_launch_identity(segment, input);
    let Some(executable) = identity.get("executable").and_then(Value::as_object) else {
        return Ok(None);
    };
    if executable.get("status").and_then(Value::as_str) != Some("verified") {
        return Ok(None);
    }
    impeccable_profile(segment, input, stable_identity_mapping(executable))
}

fn impeccable_profile(
    segment: &CommandSegment,
    input: &LocalToolEligibilityInput<'_>,
    runner: Value,
) -> Outcome<Option<PackageProfile>> {
    let mut arguments: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    if arguments.is_empty() {
        return Ok(None);
    }
    let selector = arguments.remove(0);
    if selector != "impeccable" && !SELECTOR.is_match(selector) {
        return Ok(None);
    }
    let environment_names = &segment.environment_names;
    let environment_allowed = environment_names.is_empty()
        || (environment_names.len() == 1 && environment_names[0] == CONTEXT_DIRECTORY_VARIABLE);
    if !environment_allowed {
        return Ok(None);
    }
    if !environment_names.is_empty() && !safe_context_directory(segment, input)? {
        return Ok(None);
    }
    match arguments.first() {
        Some(&"detect") => {
            arguments.remove(0);
        }
        Some(&"skills") => return Ok(None),
        _ => {}
    }
    if arguments.is_empty() {
        return Ok(None);
    }
    let mut options: Vec<String> = Vec::new();
    let mut path_count = 0_usize;
    for argument in arguments {
        if matches!(argument, "--json" | "--fast") {
            options.push(argument.to_owned());
            continue;
        }
        if argument.starts_with('-') || !safe_local_path(argument, input, false)? {
            return Ok(None);
        }
        path_count += 1;
    }
    if path_count == 0 {
        return Ok(None);
    }
    options.sort();
    Ok(Some(PackageProfile {
        identity_material: json!({
            "profile": "impeccable-local-scan:v1",
            "package": {
                "name": "impeccable",
                "selector": selector,
                "trust_mode": "continuous-package-policy-veto",
            },
            "runner": runner,
            "options": options,
            "environment_names": environment_names,
        }),
        indefinite_allowed: PINNED_SELECTOR.is_match(selector),
    }))
}

fn safe_context_directory(
    segment: &CommandSegment,
    input: &LocalToolEligibilityInput<'_>,
) -> Outcome<bool> {
    let prefix = format!("{CONTEXT_DIRECTORY_VARIABLE}=");
    let Some(token) = segment
        .tokens
        .iter()
        .find(|token| token.starts_with(&prefix))
    else {
        return Ok(false);
    };
    let value = token.split_once('=').map_or("", |(_, value)| value);
    safe_local_path(value, input, true)
}

/// An existing, non-secret local path inside the workspace or home directory.
fn safe_local_path(
    value: &str,
    input: &LocalToolEligibilityInput<'_>,
    require_directory: bool,
) -> Outcome<bool> {
    if value.is_empty() {
        return Ok(false);
    }
    // `urlparse` raises `ValueError` on a malformed netloc before any check.
    let split = urlsplit(value).map_err(|_| Abort)?;
    if !split.scheme.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '$' | '`' | '*' | '?' | '['))
    {
        return Ok(false);
    }
    let home = input.home_dir.map(py_path);
    let expanded = if value == "~" || value.starts_with("~/") {
        let Some(home) = &home else {
            return Ok(false);
        };
        if value == "~" {
            home.clone()
        } else {
            home.join(&value[2..])
        }
    } else {
        PyPath::new(value)
    };
    let cwd = py_path(input.cwd);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(&expanded.to_string())
    };
    let Some(resolved) = resolve_strict(&candidate) else {
        return Ok(false);
    };
    let kind_allowed = if require_directory {
        probe(&resolved, pyfs::is_dir)?
    } else {
        probe(&resolved, pyfs::is_file)? || probe(&resolved, pyfs::is_dir)?
    };
    if !kind_allowed {
        return Ok(false);
    }
    let secret_home = input.home_dir.or(input.user_home);
    if classify_request_secret_path(&resolved.to_string(), Some(input.cwd), secret_home).is_some() {
        return Ok(false);
    }
    let in_workspace = resolved.relative_to(&cwd).is_some();
    let in_home = home
        .as_ref()
        .is_some_and(|home| resolved.relative_to(home).is_some());
    Ok(in_workspace || in_home)
}
