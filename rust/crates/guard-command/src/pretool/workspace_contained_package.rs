//! Package-manager work admitted to the workspace sandbox.
//!
//! Scripts, builds, tests and version probes run workspace code the sandbox
//! bounds. Registry verbs and every other package ecosystem keep their
//! existing admission.
//!
//! `uv run` joins them because its project environment is the workspace's own
//! `.venv`: the interpreter it starts is already an executable root, and a
//! synced environment needs neither the network nor uv's host cache. The
//! sandbox has no network, so everything that would have to fetch keeps the
//! admission it has today rather than failing inside it: uv's installing
//! verbs, an option that adds a dependency or re-resolves one, a script
//! carrying its own dependency block, and a project whose `.venv` uv has yet
//! to materialize. Which project a verb reads moves with `--directory`,
//! `--project` and a `cd` ahead of it, so the environment is looked for where
//! the command will actually stand.
//!
//! A Python manager's queries are read by [`super::python`], `go` and `cargo`
//! by [`super::compiled`], and Composer's and Bundler's project verbs by
//! [`super::vendored`], each of which this module dispatches to.

use crate::CanonicalCommandV1;
use std::path::{Path, PathBuf};

// Node package managers. Their scripts, builds, tests and version probes run
// workspace code, which the sandbox bounds like any other local command.
const NODE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
// The runners that fetch the package they name. Only the caller's proof that
// every one of them starts an installed project tool makes them local work.
const PACKAGE_RUNNERS: &[&str] = &["npx", "bunx", "pnpx"];
// The Python managers the package firewall watches. Each can install what it
// runs, so only the queries and runner verbs [`super::python`] admits are
// local work; `uv` is the exception below.
const PYTHON_MANAGERS: &[&str] = &["pip", "pip3", "pipx", "uvx", "poetry", "pipenv"];
// uv drives a project environment the workspace holds. Only the verbs that
// read it are local: `add`, `tool`, `sync` and the rest reach a registry, and
// `pip` is local for the queries [`super::python`] admits.
const UV_LOCAL_VERBS: &[&str] = &["run", "tree", "export", "version", "pip"];
// uv options a local verb may carry: each changes what the verb reads, never
// what it has to fetch. The list is an allowlist because uv's installing
// options are many and grow: an option this module does not know keeps the
// command out, where it keeps the admission it has today.
const UV_VERB_FLAGS: &[&str] = &[
    "--frozen",
    "--locked",
    "--no-sync",
    "--no-dev",
    "--no-hashes",
    "--no-header",
    "--no-annotate",
    "--no-emit-project",
    "--all-packages",
    "--short",
    "--invert",
    "--no-dedupe",
];
// The same, for the options that take a value of their own. Their value is
// read as the option's, never as the verb's operand, so a fetching option
// behind one of them cannot pass unseen.
const UV_VERB_VALUE_OPTIONS: &[&str] = &[
    "--env-file",
    "--package",
    "--depth",
    "--format",
    "--output-file",
    "--no-emit-package",
    "--prune",
];
// uv's global options that change nothing a local verb reads. They may stand
// before the verb, so skipping them finds the verb behind them.
const UV_GLOBAL_FLAGS: &[&str] = &[
    "--offline",
    "--no-cache",
    "--native-tls",
    "--no-progress",
    "--no-config",
    "--preview",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
];
// uv's global options that move the project a verb works on, so the
// environment the check below looks for moves with them.
const UV_PROJECT_OPTIONS: &[&str] = &["--directory", "--project"];
// Verbs that fetch from, or publish to, a registry. Without network they would
// fail silently, so they keep supply-chain admission or consent instead. This
// excludes by effect; local verbs and script names are never enumerated.
const REGISTRY_VERBS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "a",
    "update",
    "up",
    "upgrade",
    "upgrade-interactive",
    "self-update",
    "udpate",
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "it",
    "cit",
    "install-test",
    "install-ci-test",
    "clean-install-test",
    "sit",
    "uninstall",
    "un",
    "unlink",
    "remove",
    "rm",
    "r",
    "link",
    "ln",
    "exec",
    "x",
    "dlx",
    "create",
    "import",
    "dedupe",
    "ddp",
    "prune",
    "audit",
    "outdated",
    "fetch",
    "cache",
    "store",
    "pm",
    "env",
    "set",
    "plugin",
    "publish",
    "unpublish",
    "login",
    "logout",
    "adduser",
    "add-user",
    "token",
    "deprecate",
    "dist-tag",
    "owner",
    "access",
    "team",
    "org",
    "star",
    "unstar",
    "view",
    "v",
    "info",
    "show",
    "search",
    "s",
    "se",
    "find",
    "ping",
    "doctor",
];

/// Where a literal `target` below the workspace moves a run that stands in
/// `directory`, or `None` when the sandbox cannot follow it there.
fn entered(directory: &Path, target: &str, workspace: &Path) -> Option<PathBuf> {
    super::cd::below(target, workspace).then(|| {
        let path = Path::new(target);
        if path.is_absolute() {
            path.to_owned()
        } else {
            directory.join(path)
        }
    })
}

/// What a `uv` command was told to do: where its verb stands, the directory
/// the verb runs in, the project whose environment it reads, and the operand
/// that follows the verb's own options.
struct UvCommand {
    verb: usize,
    directory: PathBuf,
    project: PathBuf,
    discovered: bool,
    operand: Option<usize>,
}

/// Read `arguments` as far as the verb's first operand. `--directory` moves
/// the run itself and `--project` only the project a verb reads, and either
/// may stand on one side of the verb or the other. An option this module does
/// not know hides what the command does, so the command reads as nothing.
fn uv_command(arguments: &[&str], directory: &Path, workspace: &Path) -> Option<UvCommand> {
    let mut moved: Option<&str> = None;
    let mut named: Option<&str> = None;
    let mut verb: Option<usize> = None;
    let mut operand = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let separator = *argument == "--";
        if !argument.starts_with('-') || separator {
            if verb.is_none() {
                if separator {
                    return None;
                }
                verb = Some(index);
                index += 1;
                continue;
            }
            let first = index + usize::from(separator);
            operand = (first < arguments.len()).then_some(first);
            break;
        }
        let (name, value, step) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value), 1),
            None => (*argument, arguments.get(index + 1).copied(), 2),
        };
        if value.is_none() || !argument.contains('=') {
            let known = UV_GLOBAL_FLAGS.contains(&name)
                || (verb.is_some() && UV_VERB_FLAGS.contains(&name));
            if known {
                index += 1;
                continue;
            }
        }
        let value = value?;
        if UV_PROJECT_OPTIONS.contains(&name) {
            // Wherever the two stand, uv enters `--directory` before it reads
            // `--project`, and of each only the last one counts.
            if name == "--directory" {
                moved = Some(value);
            } else {
                named = Some(value);
            }
        } else if !(verb.is_some() && UV_VERB_VALUE_OPTIONS.contains(&name)) {
            return None;
        }
        index += step;
    }
    let verb = verb?;
    let run = match moved {
        Some(target) => entered(directory, target, workspace)?,
        None => directory.to_owned(),
    };
    let project = match named {
        Some(target) => entered(&run, target, workspace)?,
        None => run.clone(),
    };
    Some(UvCommand {
        verb,
        directory: run,
        project,
        discovered: named.is_none(),
        operand,
    })
}

/// Whether `uv` runs a local verb against an environment the project already
/// holds. uv materializes one before it runs anything, so without `.venv` the
/// run would have to install, which the sandbox has no network for; those
/// commands keep the admission they have, as does an operand uv must write,
/// fetch or install for. Which project holds the environment is found the way
/// uv finds it: with no `--project` uv ascends from the directory the run
/// enters to the nearest `pyproject.toml`, so a run standing below a
/// single-project repository reaches the root's `.venv`, and the ascent stops
/// at that project as uv's does — one holding no environment is a project uv
/// would sync, not one borrowing the root's. `--project` names the project
/// outright and uv reads no other, so that path is checked where it stands.
fn local_uv_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let Some(uv) = uv_command(arguments, directory, workspace) else {
        return false;
    };
    let verb = arguments[uv.verb].to_ascii_lowercase();
    if !UV_LOCAL_VERBS.contains(&verb.as_str()) {
        return false;
    }
    if verb == "pip" {
        return super::python::local_uv_pip_work(&arguments[uv.verb + 1..], &uv.project);
    }
    if let Some(operand) = uv.operand.map(|operand| arguments[operand]) {
        // `uv version 2.0.0` writes the version into the project and locks it
        // again, a script named by URL is downloaded before it runs, and a
        // script carrying a dependency block has those installed first.
        if verb == "version"
            || operand.contains("://")
            || super::python::declares_dependencies(&uv.directory.join(operand))
        {
            return false;
        }
    }
    if !uv.discovered {
        return uv.project.join(".venv").is_dir();
    }
    super::cd::first_from(&uv.project, workspace, |probe| {
        probe.join("pyproject.toml").is_file()
    })
    .is_some_and(|project| project.join(".venv").is_dir())
}

/// Whether `name` runs Maven, by either spelling the JVM extension claims.
/// A wrapper is the same build run through the version the project pins.
fn maven_executable(name: &str) -> bool {
    matches!(name, "mvn" | "mvnw" | "mvn.cmd" | "mvnw.cmd")
}

/// Whether any segment runs a manager this module decides a verb for. The
/// fallback in [`local_package_work`] admits every executable that is not a
/// package tool, which is right for the other half of a mixed command but is
/// no evidence on its own that a manager did local work: `npx` names neither
/// a manager nor a package tool, and the package it fetches is the point.
pub(super) fn names_a_manager(model: &CanonicalCommandV1) -> bool {
    model.segments.iter().any(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            let name = super::super::executable_basename(executable).to_ascii_lowercase();
            NODE_MANAGERS.contains(&name.as_str())
                || PYTHON_MANAGERS.contains(&name.as_str())
                || super::vendored::VENDORED_MANAGERS.contains(&name.as_str())
                || matches!(name.as_str(), "uv" | "go" | "cargo")
                || maven_executable(&name)
        })
    })
}

/// Whether every package-manager segment is a manager running a local verb.
/// A registry verb anywhere before `--` keeps the whole command out, so
/// option spellings that hide the verb from a parser cannot slip one through.
/// With `installed_runners`, the caller has proved every package runner starts
/// an installed project tool, so those segments count as local work.
pub(super) fn local_package_work(
    model: &CanonicalCommandV1,
    installed_runners: bool,
    workspace: &Path,
) -> bool {
    let mut directory = Some(workspace.to_owned());
    model.segments.iter().all(|segment| {
        if installed_runners && super::runner::runner_arguments(segment).is_some() {
            return true;
        }
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        let name = super::super::executable_basename(executable).to_ascii_lowercase();
        // Which project a manager works on is the directory the chain stands
        // in by the time it runs, so a move the checks cannot follow leaves
        // no directory for the managers after it to be judged against.
        if matches!(name.as_str(), "cd" | "pushd" | "popd") {
            directory = match (&directory, segment.arguments.as_slice()) {
                (Some(current), [target]) if name != "popd" => entered(current, target, workspace),
                _ => None,
            };
            return true;
        }
        if name == "go" {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return super::compiled::local_go_work(&arguments, directory, workspace);
        }
        if maven_executable(&name) {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return super::compiled::local_maven_work(&arguments, directory);
        }
        if name == "cargo" {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return super::compiled::local_cargo_work(&arguments, directory, workspace);
        }
        if PYTHON_MANAGERS.contains(&name.as_str()) {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            return super::python::local_python_work(
                &name,
                executable,
                &segment.arguments,
                directory,
            );
        }
        if name == "uv" {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return local_uv_work(&arguments, directory, workspace);
        }
        if super::vendored::VENDORED_MANAGERS.contains(&name.as_str()) {
            let Some(directory) = directory.as_deref() else {
                return false;
            };
            return super::vendored::local_vendored_work(
                &name,
                &segment.arguments,
                &segment.environment_names,
                directory,
                workspace,
            );
        }
        if !NODE_MANAGERS.contains(&name.as_str()) {
            // A runner still here was not proved to start an installed tool,
            // so the package it names is one it fetches. The fallback below
            // admits whatever is not a package tool, which a runner is not,
            // so a manager's local verb beside it must not carry it in.
            return !PACKAGE_RUNNERS.contains(&name.as_str())
                && !super::super::generic::is_package_tool(executable);
        }
        let arguments: Vec<&str> = segment
            .arguments
            .iter()
            .map(String::as_str)
            .take_while(|argument| *argument != "--")
            .collect();
        // A bare `yarn` (or `yarn --frozen-lockfile`) installs, so the verb must
        // come first; `npm init <name>` runs a fetched initializer. The verb
        // is read behind the words [`options::skip_inert_options`] knows; any
        // other leading option, `--cwd dir` among them, still hides it.
        let behind = &arguments[options::skip_inert_options(&name, &arguments)..];
        // `yarn workspaces focus` installs the dependencies of the projects it
        // selects, and `yarn workspaces foreach` runs a command of its own in
        // each of them. The verb names neither effect, so the subcommand after
        // it decides, and neither effect is the local script work this admits.
        let workspace_fanout = name == "yarn" && behind.first() == Some(&"workspaces");
        let version_probe = behind
            .iter()
            .all(|argument| matches!(*argument, "-v" | "--version" | "-h" | "--help"));
        let leading_verb = behind
            .first()
            .is_some_and(|argument| !argument.starts_with('-'));
        let positional_init = behind
            .iter()
            .position(|argument| *argument == "init")
            .is_some_and(|index| {
                behind[index + 1..]
                    .iter()
                    .any(|argument| !argument.starts_with('-'))
            });
        // The registry scan stays on the whole list, so a selector spelled
        // like a registry verb keeps the command out rather than passing.
        !behind.is_empty()
            && (leading_verb || version_probe)
            && !workspace_fanout
            && !positional_init
            && !arguments
                .iter()
                .any(|argument| REGISTRY_VERBS.contains(&argument.to_ascii_lowercase().as_str()))
    })
}

#[path = "workspace_contained_package_options.rs"]
mod options;

#[cfg(test)]
#[path = "workspace_contained_cargo_tests.rs"]
mod cargo_tests;

#[cfg(test)]
#[path = "workspace_contained_uv_tests.rs"]
mod uv_tests;

#[cfg(test)]
#[path = "workspace_contained_go_tests.rs"]
mod go_tests;

#[cfg(test)]
#[path = "workspace_contained_maven_tests.rs"]
mod maven_tests;
