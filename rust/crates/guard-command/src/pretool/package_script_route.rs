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
//!
//! The build sink also refuses a `vite build` whose `--outDir` names anything
//! but a conventional build directory, so a direct `vite build` or a build
//! script keeps the narrow receipt only for an output directory it accepts.

#[cfg(unix)]
use crate::contained_runner::pkg_json::{object_of, read_json_with_integrity};
#[cfg(unix)]
use crate::sfrs_shlex::{split_with, PLAIN_LEXER, SCRIPT_LEXER};
use crate::CanonicalCommandV1;
#[cfg(unix)]
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use super::super::contained_wrapper::sibling_project_root;
use super::super::contained_wrapper::{contained_core, package_dir};
#[cfg(unix)]
use super::super::executable_basename;
use super::super::PathContext;

#[path = "package_script_vite.rs"]
mod package_script_vite;

#[cfg(unix)]
const PACKAGE_TEST: &str = "native_package_test_readonly_containment_required";
#[cfg(unix)]
const NODE_TOOL: &str = "native_node_tool_readonly_containment_required";
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
    if cfg!(windows) {
        if let Some(reason) = super::windows_script_reason(model, context) {
            return Some(reason);
        }
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

/// Windows runs only the direct Vite build sink, which stages a flat npm or
/// Yarn classic `node_modules` from the run directory up to the session root.
/// A package script, a pnpm store or a Plug'n'Play install keeps the review
/// prompt. Other routes are unchanged.
#[cfg(not(unix))]
fn resolved(
    model: &CanonicalCommandV1,
    reason: &'static str,
    cwd: Option<PathBuf>,
    context: PathContext<'_>,
) -> Option<&'static str> {
    if reason != NODE_BUILD {
        return Some(reason);
    }
    let segment = model.segments.first()?;
    let arguments = segment.arguments.as_slice();
    // The same name the build classification reads, so `npm.exe run build`
    // is the package script `npm run build` is and keeps the review prompt.
    let manager = crate::program_basename(segment.executable.as_deref()?);
    if matches!(manager, "npm" | "pnpm" | "bun" | "yarn")
        && (arguments.first().is_some_and(|word| word == "run")
            || super::manager_script_task(manager, arguments).is_some())
    {
        return None;
    }
    let session = std::fs::canonicalize(context.cwd?).ok()?;
    let directory = std::fs::canonicalize(cwd?).ok()?;
    if !directory.starts_with(&session)
        || !build_output_allowed(arguments, Some((&directory, &session)))
    {
        return None;
    }
    let modules =
        nearest(&directory, &session, "node_modules/vite/bin/vite.js").join("node_modules");
    let installed = std::fs::canonicalize(modules).ok()?;
    let flat = [".modules.yaml", ".pnpm"]
        .iter()
        .all(|marker| std::fs::symlink_metadata(installed.join(marker)).is_err());
    (flat && installed.join("vite/bin/vite.js").is_file()).then_some(NODE_BUILD)
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
    if !matches!(manager, "npm" | "pnpm" | "bun" | "yarn") {
        return direct_tool(reason, &segment.arguments, cwd, context);
    }
    let arguments = segment.arguments.as_slice();
    let task = super::manager_script_task(manager, arguments)
        .filter(|task| matches!(*task, "lint" | "typecheck" | "build"));
    let test = reason == PACKAGE_TEST;
    if test && manager == "bun" && arguments.first().is_some_and(|word| word == "test") {
        // `bun test` is Bun's own runner, never the package `test` script.
        return None;
    }
    if !test && task.is_none() {
        // `pnpm exec <tool>` or `bun x <tool>` runs the tool itself, not a
        // script.
        return direct_tool(reason, arguments, cwd, context);
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
/// A tool run directly (`vite build`, `npx vite build`, `node
/// node_modules/vite/bin/vite.js build`): a build keeps its receipt only for an
/// output directory the sink accepts. The launcher words before the tool are
/// never `--outDir`, so the whole argument list reads as the tool's.
fn direct_tool(
    reason: &'static str,
    arguments: &[String],
    cwd: Option<PathBuf>,
    context: PathContext<'_>,
) -> Option<&'static str> {
    if reason != NODE_BUILD {
        return Some(reason);
    }
    let found = cwd.and_then(|cwd| locations(&cwd, context));
    let roots = found
        .as_ref()
        .map(|(workspace, directory)| (directory.as_path(), workspace.as_path()));
    build_output_allowed(arguments, roots).then_some(reason)
}

/// `prepare_restricted_node_tool`'s output rule for `vite build`: the last
/// `--outDir <dir>` or `--outDir=<dir>` wins, and an empty one means the
/// default. An explicit directory must pass `validate_build_output_root`
/// without a config: a `dist`, `build` or `out` directory next to the
/// workspace root or a package manifest below it, reached without links or
/// hidden or `node_modules` components, and not a link or a file itself.
/// Without a run directory only the parts that need no filesystem are checked;
/// the sink cannot run there either.
fn build_output_allowed(arguments: &[String], roots: Option<(&Path, &Path)>) -> bool {
    let mut output = None;
    for (index, word) in arguments.iter().enumerate() {
        if let Some(value) = word.strip_prefix("--outDir=") {
            output = Some(value);
        } else if word == "--outDir" {
            let Some(value) = arguments.get(index + 1) else {
                return false;
            };
            output = Some(value.as_str());
        }
    }
    let Some(output) = output.filter(|output| !output.is_empty()) else {
        // No command-line directory: the default `dist`, or the config's
        // literal output. A config that names an output the sink cannot
        // verify must not take the narrow receipt.
        return roots.is_none_or(|(directory, workspace)| {
            package_script_vite::vite_config_output_is_verifiable(directory, workspace)
        });
    };
    let output = Path::new(output);
    if output
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
        || !output
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "dist" | "build" | "out"))
    {
        return false;
    }
    let Some((directory, workspace)) = roots else {
        return true;
    };
    // An absolute directory replaces the run directory, and `.` parts drop
    // out as they do in a Python path.
    let output: PathBuf = directory.join(output).components().collect();
    let Some(parent) = output.parent() else {
        return false;
    };
    let is_link = |path: &Path| {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    };
    if is_link(&output) || std::fs::metadata(&output).is_ok_and(|metadata| !metadata.is_dir()) {
        return false;
    }
    if parent == workspace {
        return true;
    }
    let Ok(relative) = parent.strip_prefix(workspace) else {
        return false;
    };
    if !std::fs::metadata(parent.join("package.json")).is_ok_and(|metadata| metadata.is_file()) {
        return false;
    }
    let mut reached = workspace.to_path_buf();
    relative.components().all(|part| {
        let name = part.as_os_str().to_string_lossy();
        reached.push(part);
        !name.starts_with('.') && name != "node_modules" && !is_link(&reached)
    })
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
    if reason == NODE_BUILD && !build_output_allowed(arguments, Some((directory, workspace))) {
        return None;
    }
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
    // `node_modules` may be a link to another directory in the workspace.
    // Compare the entry with that directory after both are canonical, which
    // is what the sink's path check does.
    let modules = std::fs::canonicalize(&modules).ok()?;
    let resolved = std::fs::canonicalize(modules.join(entry)).ok()?;
    (resolved.is_file() && resolved.starts_with(&modules)).then_some(reason)
}
