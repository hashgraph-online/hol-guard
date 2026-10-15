//! Package-manager script routes, resolved the way the protected sinks
//! resolve them.
//!
//! `npm|pnpm|bun run <lint|typecheck|build>` and `npm|pnpm test` only name a
//! script. The node-tool sink (`restricted_node_tool.py`) and the package-test
//! sink (`restricted_package_test.py`) read the nearest `package.json` and run
//! only a narrow set of script bodies. A narrow receipt for any other body
//! makes the sink refuse a benign command. Such a script stays an untrusted
//! package script: it keeps the generic route, which is the workspace sandbox
//! where that applies and an approval prompt otherwise.

#[cfg(unix)]
use crate::contained_runner::pkg_json::{object_of, read_json_with_integrity};
#[cfg(unix)]
use crate::sfrs_shlex::{split_with, PLAIN_LEXER, SCRIPT_LEXER};
use crate::CanonicalCommandV1;
#[cfg(unix)]
use serde_json::{Map, Value};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

#[cfg(unix)]
use super::super::contained_wrapper::sibling_project_root;
use super::super::contained_wrapper::{contained_core, package_dir};
#[cfg(unix)]
use super::super::executable_basename;
use super::super::PathContext;

#[cfg(unix)]
const PACKAGE_TEST: &str = "native_package_test_readonly_containment_required";
#[cfg(unix)]
const NODE_TOOL: &str = "native_node_tool_readonly_containment_required";
#[cfg(unix)]
const NODE_BUILD: &str = "native_node_build_output_containment_required";
const GIT: &str = "native_git_readonly_containment_required";

/// `readonly_test_reason` for the command or its verified wrapper core, with
/// package-manager script routes kept only when the sink can run the script.
pub(in crate::pretool) fn contained_test_reason(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<&'static str> {
    if let Some(reason) = super::readonly_test_reason(model) {
        return resolved(model, reason, context.cwd.map(PathBuf::from), context);
    }
    let core = contained_core(model, context)?;
    let reason = super::readonly_test_reason(&core).filter(|reason| *reason != GIT)?;
    resolved(&core, reason, core_cwd(model, context), context)
}

/// The directory the wrapper core runs in: a projected `--cwd`, a verified
/// leading `cd`, or the session directory.
fn core_cwd(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<PathBuf> {
    if let Some(projected) = package_dir::as_cd_list(model, context) {
        return core_cwd(&projected.model, context);
    }
    if model.segments.first()?.executable.as_deref() == Some("cd") {
        return super::super::segment_proof::verified_cwd_compound_context(model, context)
            .map(PathBuf::from);
    }
    context.cwd.map(PathBuf::from)
}

/// Windows runs no Node sink; its routes are unchanged.
#[cfg(not(unix))]
fn resolved(
    _model: &CanonicalCommandV1,
    reason: &'static str,
    _cwd: Option<PathBuf>,
    _context: PathContext<'_>,
) -> Option<&'static str> {
    Some(reason)
}

#[cfg(unix)]
fn resolved(
    model: &CanonicalCommandV1,
    reason: &'static str,
    cwd: Option<PathBuf>,
    context: PathContext<'_>,
) -> Option<&'static str> {
    if !matches!(reason, PACKAGE_TEST | NODE_TOOL | NODE_BUILD) {
        return Some(reason);
    }
    let segment = model.segments.first()?;
    let manager = executable_basename(segment.executable.as_deref()?);
    if !matches!(manager, "npm" | "pnpm" | "bun") {
        return Some(reason);
    }
    let arguments = segment.arguments.as_slice();
    let task = match arguments {
        [run, task] if run == "run" && matches!(task.as_str(), "lint" | "typecheck" | "build") => {
            Some(task.as_str())
        }
        _ => None,
    };
    let test = reason == PACKAGE_TEST;
    if test && manager == "bun" && arguments.first().is_some_and(|word| word == "test") {
        // `bun test` is Bun's own runner, never the package `test` script.
        return None;
    }
    if !test && task.is_none() {
        // `pnpm exec <tool>` runs the tool itself, not a script.
        return Some(reason);
    }
    let Some((workspace, directory)) = cwd.and_then(|cwd| locations(&cwd, context)) else {
        // No real directory to read: the sink cannot run it either, and no
        // narrower or broader execution is offered.
        return Some(reason);
    };
    let package = nearest(&directory, &workspace, "package.json");
    let (manifest, _) = read_json_with_integrity(&package.join("package.json"), false);
    let scripts = object_of(
        manifest
            .as_ref()
            .and_then(|manifest| manifest.get("scripts")),
    );
    if test {
        return test_script(scripts?, arguments).then_some(PACKAGE_TEST);
    }
    tool_script(scripts?, task?, &directory, &workspace)
}

#[cfg(unix)]
/// The sink's approved root and the canonical run directory, or `None` when
/// either directory does not exist.
fn locations(cwd: &Path, context: PathContext<'_>) -> Option<(PathBuf, PathBuf)> {
    let session = std::fs::canonicalize(context.cwd?).ok()?;
    let directory = std::fs::canonicalize(cwd).ok()?;
    let workspace = if directory.starts_with(&session) {
        session
    } else {
        sibling_project_root(&directory, context.home_dir?)?
    };
    Some((workspace, directory))
}

#[cfg(unix)]
/// `nearest_project_root`: the closest directory from `directory` up to
/// `workspace` holding `relative`, else `workspace`.
fn nearest(directory: &Path, workspace: &Path, relative: &str) -> PathBuf {
    if !directory.starts_with(workspace) {
        return workspace.to_path_buf();
    }
    let mut directory = directory.to_path_buf();
    while directory != workspace && std::fs::symlink_metadata(directory.join(relative)).is_err() {
        directory.pop();
    }
    directory
}

#[cfg(unix)]
/// Python truthiness of a manifest value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}

#[cfg(unix)]
fn lifecycle(scripts: &Map<String, Value>, task: &str) -> bool {
    ["pre", "post"]
        .iter()
        .any(|phase| truthy(scripts.get(&format!("{phase}{task}"))))
}

#[cfg(unix)]
/// `resolve_package_test`: an explicit `--` before arguments, no lifecycle
/// scripts, no shell expansion or effects, and `node --test` or `vitest run`.
fn test_script(scripts: &Map<String, Value>, arguments: &[String]) -> bool {
    let trailing = match arguments {
        [test, rest @ ..] if test == "test" => rest,
        [_, _, rest @ ..] => rest,
        _ => return false,
    };
    if trailing.first().is_some_and(|word| word != "--") || lifecycle(scripts, "test") {
        return false;
    }
    let Some(script) = scripts.get("test").and_then(Value::as_str) else {
        return false;
    };
    if script.contains(['$', '`', '\n', '\r']) {
        return false;
    }
    let Ok(tokens) = split_with(SCRIPT_LEXER, script) else {
        return false;
    };
    if tokens
        .iter()
        .any(|token| !token.is_empty() && token.chars().all(|c| ";&|<>".contains(c)))
    {
        return false;
    }
    match tokens.as_slice() {
        [runner, flag, ..] => {
            (matches!(executable_basename(runner), "node" | "nodejs") && flag == "--test")
                || (runner == "vitest" && flag == "run")
        }
        _ => false,
    }
}

#[cfg(unix)]
/// `prepare_restricted_node_tool` for a script: local ESLint, no-emit
/// TypeScript or `vite build`, with no fix, output or shell tokens, run from
/// the tool's own entrypoint below the nearest `node_modules`.
fn tool_script(
    scripts: &Map<String, Value>,
    task: &str,
    directory: &Path,
    workspace: &Path,
) -> Option<&'static str> {
    if lifecycle(scripts, task) {
        return None;
    }
    let tokens = split_with(PLAIN_LEXER, scripts.get(task)?.as_str()?).ok()?;
    let (tool, arguments) = tokens.split_first()?;
    let (entry, reason) = match tool.as_str() {
        "eslint" => ("eslint/bin/eslint.js", NODE_TOOL),
        "tsc" if arguments.iter().any(|word| word == "--noEmit") => {
            ("typescript/bin/tsc", NODE_TOOL)
        }
        "vite" if arguments.first().is_some_and(|word| word == "build") => {
            ("vite/bin/vite.js", NODE_BUILD)
        }
        _ => return None,
    };
    if arguments.iter().any(|word| {
        matches!(
            word.as_str(),
            ";" | "&&"
                | "||"
                | "|"
                | "|&"
                | "&"
                | "--fix"
                | "--fix-dry-run"
                | "--output-file"
                | "-o"
                | "--emitDeclarationOnly"
        ) || word.starts_with("--fix=")
            || word.starts_with("--output-file=")
    }) {
        return None;
    }
    let relative = format!("node_modules/{entry}");
    let modules = nearest(directory, workspace, &relative).join("node_modules");
    let resolved = std::fs::canonicalize(modules.join(entry)).ok()?;
    (resolved.is_file() && resolved.starts_with(&modules)).then_some(reason)
}
