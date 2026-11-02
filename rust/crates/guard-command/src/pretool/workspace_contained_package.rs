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

/// Whether any word in `scanned` reaches a registry when `manager` reads it.
/// Every word in [`REGISTRY_VERBS`] does for most of them, and `exec` is the
/// exception the manager decides: `npm exec` installs the package it names
/// when the project does not already hold it, the way `npx` does, while pnpm
/// and yarn run only what the project installed and fetch under `dlx`. Their
/// `exec` therefore reaches no registry of its own, and a run spelled with it
/// — `pnpm exec vitest run`, or the same run pinned to one package with
/// `--filter` — is the local work the sandbox bounds.
///
/// What that `exec` runs still decides the rest. A fetching program behind it
/// — `pnpm exec npm exec <package>`, `pnpm exec npx <package>` — reaches the
/// registry the outer verb does not, and the fetch is the command's effect
/// whichever word spells it, so the exemption is read against the program
/// after the verb rather than against the verb alone.
///
/// The program the verb runs is read by [`exec_runs_a_fetcher`], which sees the
/// words a `--` separator hides from this scan. The word `exec` itself is
/// exempt here wherever pnpm or yarn reads it, so a project script of their own
/// named `exec` is not mistaken for the verb.
fn scan_reaches_a_registry(manager: &str, scanned: &[&str]) -> bool {
    scanned.iter().any(|argument| {
        let argument = argument.to_ascii_lowercase();
        if argument == "exec" && matches!(manager, "pnpm" | "yarn") {
            return false;
        }
        REGISTRY_VERBS.contains(&argument.as_str())
    })
}

/// Whether a pnpm or yarn `exec` runs a program that reaches a registry itself.
/// `arguments` is the segment's whole argument list and `verb` the index of the
/// verb within it, so the target behind `pnpm exec -- npx <package>` is read
/// rather than hidden by the separator. An `exec` whose target cannot be read
/// at all keeps the review it had: there is no program for this to answer for.
fn exec_runs_a_fetcher(manager: &str, arguments: &[&str], verb: usize) -> bool {
    if !matches!(manager, "pnpm" | "yarn") || arguments.get(verb) != Some(&"exec") {
        return false;
    }
    arguments[verb + 1..]
        .iter()
        .find(|word| !word.starts_with('-'))
        .is_none_or(|target| target_keeps_its_review(target))
}

/// The index of the verb a workspace selector stands in front of. `yarn
/// workspace <name>` and pnpm's `recursive` — which pnpm also spells `multi`
/// and `m` — name which project of the workspace the command runs in rather
/// than what runs there, so the verb they carry is the word behind the
/// selector and behind the options spelled after it. Reading the leading word
/// alone would leave `yarn workspace web exec npx <package>` with no `exec`
/// for [`exec_runs_a_fetcher`] to answer for, and the fetch behind it unread.
///
/// The index returned is the selector's own when nothing stands behind it, and
/// the first word the option walk did not read otherwise. That word deciding
/// the admission is the caller's to screen: an option the walk stopped at is
/// one this route has not read, and a selector in front of it must not pass it
/// in.
fn verb_behind_a_selector(manager: &str, arguments: &[&str], verb: usize) -> usize {
    let selector = match (manager, arguments.get(verb).copied()) {
        ("yarn", Some("workspace")) => 2,
        ("pnpm", Some("recursive" | "multi" | "m")) => 1,
        _ => return verb,
    };
    let Some(behind) = arguments.get(verb + selector..) else {
        return verb;
    };
    verb + selector + options::skip_inert_options(manager, behind)
}

/// Whether the program a pnpm or yarn `exec` runs keeps the command's review.
/// The managers reach a registry through their own verbs, and a package runner
/// fetches the package it names outright, so neither is the installed project
/// tool a contained `exec` runs.
///
/// Yarn runs its `exec` argument through a shell, so a target holding
/// whitespace or shell syntax is a script rather than a program name: `yarn
/// exec 'npm install zod'` is one word here and names its install inside it.
/// What such a script does is the question this reading cannot answer, so it
/// stays at review rather than passing on the shape of the word.
///
/// A launcher is read the same way. `pnpm exec env npx <package>` and `pnpm
/// exec sh -c '<script>'` name a program that runs another program, so the
/// word after the verb is not the effect; reading only that word would admit
/// the fetch it carries.
fn target_keeps_its_review(target: &str) -> bool {
    let shell_syntax =
        |character: char| character.is_whitespace() || SHELL_SYNTAX.contains(character);
    if target.is_empty() || target.contains(shell_syntax) {
        return true;
    }
    let name = super::super::executable_basename(target).to_ascii_lowercase();
    PACKAGE_RUNNERS.contains(&name.as_str())
        || manager_program(&name)
        || LAUNCHERS.contains(&name.as_str())
}

/// Programs whose own argument is the program that runs. The effect of a
/// command spelled through one of these is whatever it launches, which this
/// reading does not follow, so an `exec` target naming one keeps its review.
const LAUNCHERS: &[&str] = &[
    "ash",
    "bash",
    "busybox",
    "command",
    "dash",
    "doas",
    "env",
    "eval",
    "exec",
    "ionice",
    "ksh",
    "nice",
    "nohup",
    "node",
    "nodejs",
    "perl",
    "python",
    "python3",
    "pwsh",
    "powershell",
    "ruby",
    "setsid",
    "sh",
    "stdbuf",
    "sudo",
    "time",
    "timeout",
    "xargs",
    "zsh",
];

/// The characters that make a word a script rather than a program name.
const SHELL_SYNTAX: &str = "&|;<>()$`\\\"'*?[]{}!#~=";

/// Whether `name` runs a manager this module decides a verb for.
fn manager_program(name: &str) -> bool {
    NODE_MANAGERS.contains(&name)
        || PYTHON_MANAGERS.contains(&name)
        || super::vendored::VENDORED_MANAGERS.contains(&name)
        || matches!(name, "uv" | "go" | "cargo")
        || maven_executable(name)
}

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
            manager_program(&name)
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
        let all_arguments: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
        let arguments: Vec<&str> = all_arguments
            .iter()
            .copied()
            .take_while(|argument| *argument != "--")
            .collect();
        // A bare `yarn` (or `yarn --frozen-lockfile`) installs, so the verb must
        // come first; `npm init <name>` runs a fetched initializer. The verb
        // is read behind the words [`options::skip_inert_options`] knows; any
        // other leading option, `--cwd dir` among them, still hides it.
        let verb = options::skip_inert_options(&name, &arguments);
        let behind = &arguments[verb..];
        // `yarn workspaces focus` installs the dependencies of the projects it
        // selects, and `yarn workspaces foreach` runs a command of its own in
        // each of them. The verb names neither effect, so the subcommand after
        // it decides, and neither effect is the local script work this admits.
        //
        // `yarn workspaces list` is the exception: it prints the workspaces the
        // project declares and runs nothing, so it carries neither effect. A
        // `workspaces` with no subcommand, and any subcommand not read here,
        // stay excluded, because what they do is the question this cannot
        // answer.
        let workspace_fanout = name == "yarn"
            && behind.first() == Some(&"workspaces")
            && behind.get(1) != Some(&"list");
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
        // The verb a workspace selector carries is read behind the selector,
        // and the option walk that finds it stops at the first option this
        // route has not read. `pnpm recursive --dir <path> exec <tool>` is
        // that shape: `--dir` moves the run to a directory the inert-value
        // walk never read, and the selector in front of it would otherwise
        // carry the command in on the leading word alone. A selector standing
        // in front of an unread option therefore keeps the command out.
        //
        // Only a selector asks this. Where none stands in front of the verb
        // the index does not move, and the leading word is whatever the route
        // already read it as -- `npm -v` is the version probe above, not an
        // option some selector hid.
        let selected = verb_behind_a_selector(&name, &arguments, verb);
        let selector_hides_an_option = selected != verb
            && arguments
                .get(selected)
                .is_some_and(|argument| argument.starts_with('-'));
        !behind.is_empty()
            && (leading_verb || version_probe)
            && !workspace_fanout
            && !positional_init
            && !selector_hides_an_option
            && !exec_runs_a_fetcher(&name, &all_arguments, selected)
            && !scan_reaches_a_registry(&name, scanned)
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
