//! Execution-context recovery for dependency-bound local Node routines.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::python_digit::python_isdigit;
use super::routine_identity::{package_tree_digest, read_package_json, TreeBudget};
use super::{probe, py_path, Abort, Outcome, TrustedTree};
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::direct_vitest::semver_spec_matches;
use crate::sfrs_developer_graph::starts_with_literal_cd;
use crate::sfrs_gh_pyshim::is_executable;
use crate::sfrs_interpreter_trust::resolve_strict;
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::sfrs_source_edit_context::shell_execution_context_validation_reason;
use crate::sfrs_static_safety::leading_literal_cd_workspace_root;
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};

const WRITE_FLAGS: [&str; 6] = [
    "--cache",
    "--cache-location",
    "--fix",
    "--fix-dry-run",
    "--fix-type",
    "--output-file",
];
const ESLINT_FLAGS: [&str; 4] = [
    "--no-cache",
    "--no-error-on-unmatched-pattern",
    "--no-warn-ignored",
    "--quiet",
];
const DYNAMIC_CHARACTERS: [char; 12] = ['$', '`', '>', '<', '|', '&', '*', '?', '[', ']', '{', '}'];
const DEPENDENCY_SECTIONS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) struct RoutineProfile {
    pub(super) tool_name: &'static str,
    pub(super) capability: &'static str,
    pub(super) identity_material: Value,
}

struct RoutineContext {
    context: ShellExecutionContext,
    workspace: PathBuf,
    runner: &'static str,
    package: &'static str,
    binding: Value,
}

fn runner_package(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "eslint" => Some(("eslint", "eslint")),
        "next" => Some(("next", "next")),
        "tsc" => Some(("tsc", "typescript")),
        _ => None,
    }
}

/// `routine_local_node_approval_profile`.
pub(super) fn routine_profile(
    command: &str,
    home: &Path,
    trusted_trees: &[TrustedTree<'_>],
) -> Outcome<Option<RoutineProfile>> {
    let Some(routine) = execution_context(command, home, trusted_trees)? else {
        return Ok(None);
    };
    let Some(workspace) = routine.context.workspace_root.clone() else {
        return Ok(None);
    };
    let workspace_path = py_path(&workspace);
    let binding = if workspace == routine.workspace {
        routine.binding
    } else {
        match workspace_runner_binding(
            &workspace_path,
            routine.runner,
            routine.package,
            trusted_trees,
        )? {
            Some(binding) => binding,
            None => return Ok(None),
        }
    };
    let identity = (|| -> Outcome<(Value, String, String)> {
        let workspace_identity = super::routine_identity::workspace_identity(&workspace_path)?;
        let (configuration_digest, configuration_packages) =
            super::routine_config::configuration_identity(&workspace_path, routine.runner)?;
        let mut closure_roots = vec![routine.package.to_owned()];
        closure_roots.extend(configuration_packages);
        let closure_digest =
            super::routine_identity::dependency_closure_digest(&workspace_path, &closure_roots)?;
        Ok((workspace_identity, configuration_digest, closure_digest))
    })();
    // The retired profile caught `OSError`, `RuntimeError` and `ValueError` here.
    let Ok((workspace_identity, configuration_digest, closure_digest)) = identity else {
        return Ok(None);
    };
    let (tool_name, capability) = match routine.runner {
        "eslint" => ("ESLint", "lint"),
        "next" => ("Next.js", "build"),
        _ => ("TypeScript", "typecheck"),
    };
    Ok(Some(RoutineProfile {
        tool_name,
        capability,
        identity_material: json!({
            "version": 1,
            "package": routine.package,
            "binding": binding,
            "dependency_closure_digest": closure_digest,
            "configuration_digest": configuration_digest,
            "workspace": workspace_identity,
            "grammar": "routine-local-node-v1",
        }),
    }))
}

/// `routine_local_node_execution_context`: one literal workspace switch
/// followed by a bound local validation runner and an optional bounded filter.
fn execution_context(
    command: &str,
    home: &Path,
    trusted_trees: &[TrustedTree<'_>],
) -> Outcome<Option<RoutineContext>> {
    if ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command.contains(marker))
    {
        return Ok(None);
    }
    let initial = model_shell_execution_context(command, Some(home), Some(home), Some(home));
    let Some(workspace) = leading_literal_cd_workspace_root(&initial, home) else {
        return Ok(None);
    };
    let home_resolved = pyfs::resolve(&py_path(home)).ok_or(Abort)?;
    if py_path(&workspace) == home_resolved {
        return Ok(None);
    }
    let context =
        model_shell_execution_context(command, Some(&workspace), Some(&workspace), Some(home));
    if !starts_with_literal_cd(&context)
        || shell_execution_context_validation_reason(&context).is_some()
        || !matches!(context.segments.len(), 2 | 3)
    {
        return Ok(None);
    }
    let runner_segment = &context.segments[1];
    let (name, index) = shell_segment_primary_command(&runner_segment.tokens);
    let Some((runner, package)) = name.as_deref().and_then(runner_package) else {
        return Ok(None);
    };
    let Some(index) = index else {
        return Ok(None);
    };
    if !controlled_by(runner_segment, "&&") {
        return Ok(None);
    }
    let tokens = &runner_segment.tokens;
    if index >= tokens.len() || !safe_environment(&tokens[..index], runner) {
        return Ok(None);
    }
    if tokens[index] != format!("./node_modules/.bin/{runner}") {
        return Ok(None);
    }
    let mut args: Vec<&str> = tokens[index + 1..].iter().map(String::as_str).collect();
    if args.last() == Some(&"2>&1") {
        args.pop();
    }
    if !routine_args(runner, &args) {
        return Ok(None);
    }
    let Some(binding) =
        workspace_runner_binding(&py_path(&workspace), runner, package, trusted_trees)?
    else {
        return Ok(None);
    };
    if context.segments.len() == 3 && !bounded_output_filter(&context.segments[2]) {
        return Ok(None);
    }
    Ok(Some(RoutineContext {
        context,
        workspace,
        runner,
        package,
        binding,
    }))
}

fn controlled_by(segment: &ShellExecutionSegment, control: &str) -> bool {
    segment.control_before.len() == 1 && segment.control_before[0] == control
}

/// ASCII digits without a leading zero, `min..=max` characters long.
fn bounded_ascii_number(text: &str, min: usize, max: usize) -> Option<u32> {
    let valid = (min..=max).contains(&text.len())
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    if !valid {
        return None;
    }
    text.parse().ok()
}

fn safe_environment(tokens: &[String], runner: &str) -> bool {
    if runner != "next" {
        return tokens.is_empty();
    }
    let mut remaining = tokens;
    if remaining.first().is_some_and(|token| {
        token
            .strip_prefix("HOL_NEXT_BUILD_CPUS=")
            .and_then(|value| bounded_ascii_number(value, 1, 2))
            .is_some_and(|value| (1..=64).contains(&value))
    }) {
        remaining = &remaining[1..];
    }
    if remaining.first().is_some_and(|token| {
        token
            .strip_prefix("NODE_OPTIONS=--max-old-space-size=")
            .and_then(|value| bounded_ascii_number(value, 3, 5))
            .is_some_and(|value| (256..=32768).contains(&value))
    }) {
        remaining = &remaining[1..];
    }
    remaining.is_empty()
}

fn routine_args(runner: &str, args: &[&str]) -> bool {
    match runner {
        "next" => args == ["build", "--webpack"],
        "tsc" => typescript_args(args),
        _ => eslint_args(args),
    }
}

fn typescript_args(args: &[&str]) -> bool {
    if args.is_empty() || args.iter().filter(|arg| **arg == "--noEmit").count() != 1 {
        return false;
    }
    let mut remaining: Vec<&str> = args.to_vec();
    let Some(position) = remaining.iter().position(|arg| *arg == "--noEmit") else {
        return false;
    };
    remaining.remove(position);
    if remaining.len() >= 2 && remaining[0] == "--pretty" && remaining[1] == "false" {
        remaining = remaining[2..].to_vec();
    }
    if remaining
        .first()
        .is_some_and(|arg| matches!(*arg, "-p" | "--project"))
    {
        remaining.remove(0);
        if remaining.is_empty() || remaining.remove(0) != "tsconfig.json" {
            return false;
        }
    }
    remaining.is_empty()
}

fn eslint_args(args: &[&str]) -> bool {
    let writes = args.iter().any(|token| {
        WRITE_FLAGS.iter().any(|flag| {
            *token == *flag
                || token
                    .strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
        })
    });
    if args.is_empty() || writes {
        return false;
    }
    let mut targets = 0_usize;
    let mut index = 0;
    while index < args.len() {
        let token = args[index];
        if ESLINT_FLAGS.contains(&token) {
            index += 1;
            continue;
        }
        if token == "--max-warnings" {
            if index + 1 >= args.len() || !python_isdigit(args[index + 1]) {
                return false;
            }
            index += 2;
            continue;
        }
        if token.starts_with('-') || dynamic_or_external(token) {
            return false;
        }
        targets += 1;
        index += 1;
    }
    targets > 0
}

fn dynamic_or_external(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with('~')
        || token
            .chars()
            .any(|character| DYNAMIC_CHARACTERS.contains(&character))
        || token.split('/').any(|part| part == "..")
}

fn bounded_output_filter(segment: &ShellExecutionSegment) -> bool {
    let tokens = &segment.tokens;
    let (name, index) = shell_segment_primary_command(tokens);
    let (Some(name), Some(index)) = (name, index) else {
        return false;
    };
    if !matches!(name.as_str(), "head" | "tail") || !controlled_by(segment, "|") {
        return false;
    }
    if tokens.get(index) != Some(&name) {
        return false;
    }
    let args = &tokens[index + 1..];
    args.len() == 1
        && args[0]
            .strip_prefix('-')
            .and_then(|count| bounded_ascii_number(count, 1, 3))
            .is_some()
}

/// `_workspace_runner_binding`: the runner is the trusted, locked, declared
/// package's own executable inside the workspace.
fn workspace_runner_binding(
    workspace: &PyPath,
    runner: &str,
    package_name: &str,
    trusted_trees: &[TrustedTree<'_>],
) -> Outcome<Option<Value>> {
    let node_modules = workspace.join("node_modules");
    let package_dir = node_modules.join(package_name);
    let Some(package) = read_package_json(&package_dir.join("package.json")) else {
        return Ok(None);
    };
    if package.get("name").and_then(Value::as_str) != Some(package_name) {
        return Ok(None);
    }
    let installed = package.get("version").and_then(Value::as_str);
    let declared = declared_dependency_version(workspace, package_name);
    let mut lockfiles = Vec::new();
    for name in ["bun.lock", "package-lock.json"] {
        let lockfile = workspace.join(name);
        if probe(&lockfile, pyfs::exists)? {
            lockfiles.push(lockfile);
        }
    }
    let (Some(installed), Some(declared)) = (installed, declared) else {
        return Ok(None);
    };
    if lockfiles.len() != 1 {
        return Ok(None);
    }
    let Some((version, integrity)) = locked_package_identity(&lockfiles[0], package_name) else {
        return Ok(None);
    };
    let Some(tree_digest) = trusted_tree_digest(trusted_trees, package_name, &version, &integrity)
    else {
        return Ok(None);
    };
    if version != installed
        || !semver_spec_matches(&declared, installed)
        || !package_tree_digest(&package_dir, false, &mut TreeBudget::default())
            .is_ok_and(|digest| digest == tree_digest)
    {
        return Ok(None);
    }
    let Some(target) = package_bin_target(&package, runner) else {
        return Ok(None);
    };
    let resolved = (|| {
        let workspace_root = resolve_strict(workspace)?;
        let package_root = resolve_strict(&package_dir)?;
        let executable = resolve_strict(&node_modules.join(".bin").join(runner))?;
        let expected = resolve_strict(&package_dir.join(&target))?;
        package_root.relative_to(&workspace_root)?;
        executable.relative_to(&package_root)?;
        Some((workspace_root, executable, expected))
    })();
    let Some((workspace_root, executable, expected)) = resolved else {
        return Ok(None);
    };
    if executable != expected
        || !probe(&executable, pyfs::is_file)?
        || !is_executable(&executable.to_string())
    {
        return Ok(None);
    }
    let relative = executable
        .relative_to(&workspace_root)
        .map(|parts| {
            if parts.is_empty() {
                ".".to_owned()
            } else {
                parts.join("/")
            }
        })
        .ok_or(Abort)?;
    Ok(Some(json!({
        "package": package_name,
        "version": version,
        "integrity": integrity,
        "tree_digest": tree_digest,
        "executable": relative,
    })))
}

fn trusted_tree_digest(
    trusted_trees: &[TrustedTree<'_>],
    package_name: &str,
    version: &str,
    integrity: &str,
) -> Option<String> {
    trusted_trees
        .iter()
        .find(|tree| tree.0 == package_name && tree.1 == version && tree.2 == integrity)
        .map(|tree| tree.3.to_owned())
}

fn package_bin_target(package: &Map<String, Value>, runner: &str) -> Option<String> {
    match package.get("bin") {
        Some(Value::String(target)) => {
            (package.get("name").and_then(Value::as_str) == Some(runner)).then(|| target.clone())
        }
        Some(Value::Object(targets)) => targets
            .get(runner)
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

fn declared_dependency_version(workspace: &PyPath, package_name: &str) -> Option<String> {
    let package = read_package_json(&workspace.join("package.json"))?;
    DEPENDENCY_SECTIONS.iter().find_map(|section| {
        package
            .get(*section)
            .and_then(Value::as_object)
            .and_then(|dependencies| dependencies.get(package_name))
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

/// `_locked_package_identity`: `(version, integrity)` from the one lockfile.
fn locked_package_identity(path: &PyPath, package_name: &str) -> Option<(String, String)> {
    let text = super::routine_identity::read_bounded_text(path)?;
    let bun = path.name() == "bun.lock";
    let lock: Value = if bun {
        crate::jsonc::loads_jsonc(&text).ok()?
    } else {
        serde_json::from_str(&text).ok()?
    };
    let packages = lock.as_object()?.get("packages")?.as_object()?;
    if bun {
        let entry = packages
            .get(package_name)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        if entry.len() < 4 {
            return None;
        }
        let selector = entry[0].as_str()?;
        let integrity = entry[3].as_str()?;
        if !integrity.starts_with("sha512-") {
            return None;
        }
        let version = selector.strip_prefix(&format!("{package_name}@"))?;
        return Some((version.to_owned(), integrity.to_owned()));
    }
    let entry = packages
        .get(&format!("node_modules/{package_name}"))?
        .as_object()?;
    let version = entry.get("version")?.as_str()?;
    let integrity = entry.get("integrity")?.as_str()?;
    integrity
        .starts_with("sha512-")
        .then(|| (version.to_owned(), integrity.to_owned()))
}
