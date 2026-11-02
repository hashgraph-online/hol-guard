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
use crate::contained_package_test::lifecycle;
#[cfg(unix)]
use crate::contained_runner::pkg_json::{object_of, read_json_with_integrity};
#[cfg(unix)]
use crate::sfrs_shlex::{split_with, PLAIN_LEXER};
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

#[path = "bun_package_entry.rs"]
mod bun_package_entry;

#[cfg(unix)]
const PACKAGE_TEST: &str = "native_package_test_readonly_containment_required";
const NODE_TOOL: &str = "native_node_tool_readonly_containment_required";
const NODE_BUILD: &str = "native_node_build_output_containment_required";
const GIT: &str = "native_git_readonly_containment_required";

/// `readonly_test_reason` for the command or its verified wrapper core, with
/// package-manager script routes kept only when the sink can run the script.
pub(in crate::pretool) fn contained_test_reason(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<&'static str> {
    // `bun node_modules/<package>/<entry>` is the run `node` names.
    let spelled = bun_package_entry::node_spelling(model);
    let model = spelled.as_ref().unwrap_or(model);
    if let Some(reason) = super::readonly_test_reason(model, context.cwd.map(Path::new)) {
        return resolved(model, reason, context.cwd.map(PathBuf::from), context);
    }
    if cfg!(windows) {
        if let Some(reason) = super::windows_script_reason(model, context) {
            return Some(reason);
        }
    }
    let core = contained_core(model, context)?;
    // The core runs in its own directory, so the reading that depends on it
    // and the receipt that records it are given the same answer.
    let cwd = core_cwd(model, context);
    let reason =
        super::readonly_test_reason(&core, cwd.as_deref()).filter(|reason| *reason != GIT)?;
    resolved(&core, reason, cwd, context)
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

/// Windows runs the direct Vite build and the direct read-only tool sinks,
/// which stage a flat npm or Yarn classic `node_modules` from the run
/// directory up to the session root. A package script, a pnpm store or a
/// Plug'n'Play install keeps the review prompt. Other routes are unchanged.
#[cfg(not(unix))]
fn resolved(
    model: &CanonicalCommandV1,
    reason: &'static str,
    cwd: Option<PathBuf>,
    context: PathContext<'_>,
) -> Option<&'static str> {
    if reason != NODE_BUILD && reason != NODE_TOOL {
        return Some(reason);
    }
    let segment = model.segments.first()?;
    let arguments = segment.arguments.as_slice();
    // The same name the build classification reads, so `npm.exe run build`
    // is the package script `npm run build` is and keeps the review prompt.
    let manager = crate::program_basename(segment.executable.as_deref()?);
    // A manager's `exec` spelling runs a local bin, not a script body.
    let local_run = super::manager_local_bin_arguments(manager, arguments).is_some();
    if matches!(manager, "npm" | "pnpm" | "bun" | "yarn")
        && !local_run
        && (arguments
            .first()
            .is_some_and(|word| crate::contained_argv::names_script_run_verb(manager, word))
            || super::manager_script_task(manager, arguments).is_some())
    {
        return None;
    }
    let session = std::fs::canonicalize(context.cwd?).ok()?;
    let directory = std::fs::canonicalize(cwd?).ok()?;
    if !directory.starts_with(&session) {
        return None;
    }
    let entries: &[&str] = if reason == NODE_BUILD {
        if !build_output_allowed(arguments, Some((&directory, &session))) {
            return None;
        }
        &["vite/bin/vite.js"]
    } else {
        staged_tool_entries(manager, arguments)?
    };
    staged_install(&directory, &session, entries).then_some(reason)
}

/// The entrypoints a read-only tool run stages, for the invocation forms the
/// classifier admits on Windows: a local bin, `npx`, `bunx`, a manager's
/// `exec` spelling, or Node started on the tool's own entrypoint.
#[cfg(not(unix))]
fn staged_tool_entries(program: &str, arguments: &[String]) -> Option<&'static [&'static str]> {
    let tool = match program {
        "npx" | "bunx" => arguments.first()?.as_str(),
        // Only a manager's bare `exec` spelling is a local-bin run.
        "npm" | "pnpm" | "yarn" => super::manager_local_bin_arguments(program, arguments)?
            .first()?
            .as_str(),
        "node" | "nodejs" => crate::contained_node_tool::entry_tool(arguments.first()?),
        other => other,
    };
    // `vite build` is the build-output route, which stages its entry above.
    if tool == "vite" {
        return None;
    }
    crate::contained_node_tool::node_tool_modes::tool_entries(tool).map(|(_, entries)| entries)
}

/// Whether the nearest install carrying one of `entries` is a flat npm or
/// Yarn classic `node_modules` the Windows runner can stage.
#[cfg(not(unix))]
fn staged_install(directory: &Path, session: &Path, entries: &[&str]) -> bool {
    entries.iter().any(|entry| {
        let relative = format!("node_modules/{entry}");
        let modules = nearest(directory, session, &relative).join("node_modules");
        let Ok(installed) = std::fs::canonicalize(modules) else {
            return false;
        };
        [".modules.yaml", ".pnpm"]
            .iter()
            .all(|marker| std::fs::symlink_metadata(installed.join(marker)).is_err())
            && installed.join(entry).is_file()
    })
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
    let task = super::manager_script_task(manager, arguments);
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
        // narrower or broader execution is offered. A conventional name says
        // what the script does on its own; any other name is only as good as
        // the body behind it, so without the manifest it stays a package
        // script and keeps the generic route. A checking name runs read-only
        // whatever the run passes on, and the words it passes have already
        // been read for writes and shell effects, so a tail rides with it. A
        // build's receipt names an output directory instead, and `--outDir`
        // arriving in that tail can only be read against the manifest, so a
        // build with a tail keeps the generic route.
        return (test
            || task.is_some_and(|(task, tail)| match task {
                "lint" | "typecheck" => true,
                "build" => tail.is_empty(),
                _ => false,
            }))
        .then_some(reason);
    };
    let package = nearest(&directory, &workspace, "package.json");
    let (manifest, _) = read_json_with_integrity(&package.join("package.json"), false);
    let scripts = object_of(
        manifest
            .as_ref()
            .and_then(|manifest| manifest.get("scripts")),
    );
    let scripts = scripts?;
    if test {
        // The sink reads the same manifest and runs whatever the body spells,
        // so a test-named entry keeps the package route even when the body is
        // a read-only tool rather than a runner. A body the sink refuses
        // leaves the command on the generic route.
        if !test_script(manager, scripts, arguments) {
            return None;
        }
        // A tool body is gated as that tool, and the tool's own gate includes
        // being installed where the sink looks. Without that check a
        // `test:types` entry holding `tsc --noEmit` would take the package
        // route with no local TypeScript, and the sink would fail the run
        // that the generic route would have put to the user instead.
        if let Some((tool, tool_arguments)) =
            crate::contained_package_test::script_tool_body(manager, arguments, Some(scripts))
        {
            let (_, entries, _) =
                crate::contained_node_tool::supported_tool(&tool, &tool_arguments)?;
            return tool_entry_installed(entries, &directory, &workspace).then_some(PACKAGE_TEST);
        }
        return Some(PACKAGE_TEST);
    }
    let (task, tail) = task?;
    tool_script(scripts, task, tail, &directory, &workspace)
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
            crate::vite_output::config_output_is_verifiable(directory, workspace)
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
/// `resolve_package_test`: the sink's own reading of the declared script, so
/// the route offers the narrow receipt only for a run the sink will resolve.
fn test_script(manager: &str, scripts: &Map<String, Value>, arguments: &[String]) -> bool {
    crate::contained_package_test::script_tokens(manager, arguments, Some(scripts)).is_ok()
}

#[cfg(unix)]
/// `prepare_restricted_node_tool` for a script: local ESLint, no-emit
/// TypeScript or `vite build`, with no fix, output or shell tokens, run from
/// the tool's own entrypoint below the nearest `node_modules`.
fn tool_script(
    scripts: &Map<String, Value>,
    task: &str,
    tail: &[String],
    directory: &Path,
    workspace: &Path,
) -> Option<&'static str> {
    if lifecycle(scripts, task) {
        return None;
    }
    let tokens = split_with(PLAIN_LEXER, scripts.get(task)?.as_str()?).ok()?;
    let (tool, body) = tokens.split_first()?;
    // The words after `--` are the run's own arguments, so the tool is gated
    // holding them: an `--outDir` or a redirection arriving that way is read
    // here rather than reaching the sink unseen.
    if !crate::contained_node_tool::passed_tail_reports_only(tool, tail) {
        return None;
    }
    let passed = [body, tail].concat();
    let arguments = passed.as_slice();
    let (_, entries, mode) = crate::contained_node_tool::supported_tool(tool, arguments)?;
    let build = mode == crate::contained_node_tool::ToolMode::Build;
    let reason = if build { NODE_BUILD } else { NODE_TOOL };
    if build && !build_output_allowed(arguments, Some((directory, workspace))) {
        return None;
    }
    if crate::contained_node_tool::writes_or_chains(arguments) {
        return None;
    }
    tool_entry_installed(entries, directory, workspace).then_some(reason)
}

#[cfg(unix)]
/// Whether the tool is installed where the sink resolves it.
///
/// A tool that publishes one entrypoint per major is installed under
/// whichever spelling its version uses, and the sink resolves the same set.
/// A receipt issued for a tool that is not there names a run the sink cannot
/// make, so the command belongs on the generic route instead.
fn tool_entry_installed(entries: &[&str], directory: &Path, workspace: &Path) -> bool {
    entries.iter().any(|entry| {
        let relative = format!("node_modules/{entry}");
        let modules = nearest(directory, workspace, &relative).join("node_modules");
        // `node_modules` may be a link to another directory in the workspace.
        // Compare the entry with that directory after both are canonical,
        // which is what the sink's path check does.
        let Ok(modules) = std::fs::canonicalize(&modules) else {
            return false;
        };
        std::fs::canonicalize(modules.join(entry))
            .is_ok_and(|resolved| resolved.is_file() && resolved.starts_with(&modules))
    })
}
