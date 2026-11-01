//! Package-manager work admitted to the workspace sandbox.
//!
//! Scripts, builds, tests and version probes run workspace code the sandbox
//! bounds. Registry verbs and every other package ecosystem keep their
//! existing admission.
//!
//! `uv run` joins them because its project environment is the workspace's own
//! `.venv`: the interpreter it starts is already an executable root, and a
//! synced environment needs neither the network nor uv's host cache. Reading
//! a `uv` command that far is [`uv`]'s work.
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
// local work; `uv` is the exception [`uv`] reads.
const PYTHON_MANAGERS: &[&str] = &["pip", "pip3", "pipx", "uvx", "poetry", "pipenv"];
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
pub(super) fn entered(directory: &Path, target: &str, workspace: &Path) -> Option<PathBuf> {
    super::cd::below(target, workspace).then(|| {
        let path = Path::new(target);
        if path.is_absolute() {
            super::cd::canonical_below(path, workspace)
        } else {
            directory.join(path)
        }
    })
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
            // A leading `-C` moves the run before go reads the verb, so it is
            // judged as the `cd` it is: the directory it names is followed
            // where the sandbox can follow it there, and the verb behind it is
            // read against that directory rather than this one.
            let (started, verb) = match super::compiled::go_chdir(&arguments) {
                Some((target, read)) => match entered(directory, target, workspace) {
                    Some(moved) => (moved, read),
                    None => return false,
                },
                None => (directory.to_owned(), 0),
            };
            return super::compiled::local_go_work(&arguments[verb..], &started, workspace);
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
                workspace,
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
            return uv::local_uv_work(&arguments, directory, workspace);
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
        // `-V` is the other short spelling of the same probe. A manager
        // that reads it as "verbose" still has no verb to run, so either
        // reading prints a version or a usage line and exits.
        let version_probe = behind
            .iter()
            .all(|argument| matches!(*argument, "-v" | "-V" | "--version" | "-h" | "--help"));
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
        // A group verb names a family of subcommands rather than an effect of
        // its own, so the word alone cannot say whether a registry is
        // reached; the subcommand after it does. When that subcommand only
        // reports what is already on disk, [`groups::reads`] has read every
        // word behind the options, and the registry scan runs over the
        // options alone rather than refusing the group word and the ordinary
        // local reads spelled with it.
        let group_read = groups::reads(behind);
        // The registry scan stays on the whole list otherwise, so a selector
        // spelled like a registry verb keeps the command out rather than
        // passing.
        let scanned = if group_read {
            &arguments[..arguments.len() - behind.len()]
        } else {
            &arguments[..]
        };
        !behind.is_empty()
            && (leading_verb || version_probe)
            && !workspace_fanout
            && !positional_init
            && !scanned
                .iter()
                .any(|argument| REGISTRY_VERBS.contains(&argument.to_ascii_lowercase().as_str()))
    })
}

#[path = "workspace_contained_package_groups.rs"]
mod groups;

#[path = "workspace_contained_package_uv.rs"]
mod uv;

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
