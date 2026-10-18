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
//! `go` joins them for the same reason, with its module cache and toolchain
//! read-only beside the workspace. A verb only counts as local inside a
//! module the directory it runs in holds, since outside one go resolves
//! imports through the proxy. An argument naming a version, and `go list`'s
//! `-u` and `-versions`, reach that proxy even inside a module, so each
//! keeps the admission it has.
//!
//! Cargo joins them for the verbs that compile what the workspace already
//! has. Its `build.rs` scripts and proc macros run dependency code like npm
//! scripts, which is what the sandbox bounds. The crate sources it reads live
//! in `~/.cargo/registry` and `~/.cargo/git` and its toolchain in `~/.rustup`,
//! each granted read-only; the run gets its own `CARGO_HOME`, with those two
//! caches linked in, so cargo takes its locks and writes its own state inside
//! the private tree. `~/.cargo/config.toml` and `~/.cargo/credentials.toml`
//! stay out, which keeps registry tokens out of the run, and the fetching
//! verbs keep the admission they have today.
use crate::CanonicalCommandV1;
use std::path::{Path, PathBuf};

// Node package managers. Their scripts, builds, tests and version probes run
// workspace code, which the sandbox bounds like any other local command.
const NODE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
// The runners that fetch the package they name. Only the caller's proof that
// every one of them starts an installed project tool makes them local work.
const PACKAGE_RUNNERS: &[&str] = &["npx", "bunx", "pnpx"];
pub(super) const NODE_PACKAGE_EXTENSION: &str = "command.package.node";
const PYTHON_PACKAGE_EXTENSION: &str = "command.package.python";
const GO_PACKAGE_EXTENSION: &str = "command.package.go";
const RUST_PACKAGE_EXTENSION: &str = "command.package.rust";
// The package-firewall permissions that mark a manager's use. They record
// which ecosystem ran, not a risk the run carries, so a local verb below one
// of them is still ordinary workspace work.
pub(crate) const PACKAGE_EXTENSIONS: &[&str] = &[
    NODE_PACKAGE_EXTENSION,
    PYTHON_PACKAGE_EXTENSION,
    GO_PACKAGE_EXTENSION,
    RUST_PACKAGE_EXTENSION,
];
// The Python managers the package firewall watches. Each installs what it
// runs, so none of their verbs is local work; `uv` is the exception below.
const PYTHON_MANAGERS: &[&str] = &["pip", "pip3", "pipx", "uvx", "poetry", "pipenv"];
// uv drives a project environment the workspace holds. Only the verbs that
// read it are local: `pip`, `add`, `tool` and the rest reach a registry.
const UV_LOCAL_VERBS: &[&str] = &["run", "tree", "export", "version"];
// A Go build compiles the sources the module cache already holds and writes
// its objects to a private build cache. Only the verbs that stay there are
// local: `get`, `install`, `mod` and `work` reach a registry, and `tool` and
// `clean` are neither a build nor a read.
const GO_LOCAL_VERBS: &[&str] = &[
    "build", "test", "vet", "fmt", "list", "doc", "env", "version", "run", "generate",
];
// A cargo build compiles the crate sources the registry cache already holds
// into a target directory the workspace owns. Only the verbs that stay there
// are local: `install`, `add`, `update`, `publish` and the rest reach a
// registry, and `vendor` and `fetch` exist to populate a cache.
const CARGO_LOCAL_VERBS: &[&str] = &[
    "build", "b", "test", "t", "check", "c", "clippy", "fmt", "doc", "d", "run", "r", "bench",
    "tree", "metadata", "version", "nextest",
];
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
// How much of a script is read to find the dependency block. PEP 723 allows
// the block anywhere in the file, so the whole script is read, up to a bound
// that keeps a hook from paging in an arbitrarily large one.
const SCRIPT_BYTES: u64 = 1 << 20;
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

/// Whether `go` runs a local verb inside a module that `directory` holds.
/// Outside a module these verbs read the wider GOPATH, and the sandbox has no
/// network to resolve a package by import path, so they keep the admission
/// they have. A version an argument names is one go resolves through the
/// module proxy, and `go list`'s `-u` and `-versions` ask the proxy what else
/// a module has, as does `-retracted`, so each of those keeps that admission
/// too.
fn local_go_work(arguments: &[&str], directory: &Path) -> bool {
    let Some((verb, rest)) = arguments.split_first() else {
        return false;
    };
    GO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str())
        && !rest
            .iter()
            .any(|argument| names_a_go_fetch(argument) || argument.contains('@'))
        && directory.join("go.mod").is_file()
}

/// Whether `cargo` runs a local verb against a package that `directory`
/// holds. A leading `+toolchain` selects a rustup toolchain, which the run
/// may read. Outside a package cargo has nothing to compile and would search
/// upward out of the workspace, so those commands keep the admission they
/// have.
fn local_cargo_work(arguments: &[&str], directory: &Path) -> bool {
    arguments
        .iter()
        .find(|argument| !argument.starts_with('+'))
        .is_some_and(|verb| CARGO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()))
        && directory.join("Cargo.toml").is_file()
}

/// Whether an argument names one of the flags that send a Go verb to a module
/// proxy. Go's flag package reads one dash or two alike and takes a boolean's
/// value either as the next argument or behind an `=`, so the name is read
/// the same way here. A flag turned off by its value still keeps the command
/// out: a run that names it is one the sandbox has no reason to decide for.
fn names_a_go_fetch(argument: &str) -> bool {
    let name = argument.trim_start_matches('-');
    if !(1..=2).contains(&(argument.len() - name.len())) {
        return false;
    }
    matches!(
        name.split_once('=').map_or(name, |(name, _)| name),
        "u" | "versions" | "retracted"
    )
}

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
        operand,
    })
}

/// Whether `path` is a script that carries its own dependencies. uv installs
/// those into a fresh environment before it runs the script, which the
/// sandbox has no network for.
fn declares_dependencies(path: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut text = Vec::new();
    if file.take(SCRIPT_BYTES).read_to_end(&mut text).is_err() {
        return false;
    }
    String::from_utf8_lossy(&text)
        .lines()
        .any(|line| line.trim_end() == "# /// script")
}

/// Whether `uv` runs a local verb against an environment the project
/// already holds. uv materializes a project environment before it runs
/// anything, so without `.venv` the run would have to install, which the
/// sandbox has no network for; those commands keep the admission they have.
/// An operand uv has to write, fetch or install for keeps it for the same
/// reason.
fn local_uv_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let Some(uv) = uv_command(arguments, directory, workspace) else {
        return false;
    };
    let verb = arguments[uv.verb].to_ascii_lowercase();
    if !UV_LOCAL_VERBS.contains(&verb.as_str()) {
        return false;
    }
    if let Some(operand) = uv.operand.map(|operand| arguments[operand]) {
        // `uv version 2.0.0` writes the version into the project and locks it
        // again, a script named by URL is downloaded before it runs, and a
        // script carrying a dependency block has those installed first.
        if verb == "version"
            || operand.contains("://")
            || declares_dependencies(&uv.directory.join(operand))
        {
            return false;
        }
    }
    uv.project.join(".venv").is_dir()
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
                || matches!(name.as_str(), "uv" | "go" | "cargo")
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
            return local_go_work(&arguments, directory);
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
            return local_cargo_work(&arguments, directory);
        }
        if PYTHON_MANAGERS.contains(&name.as_str()) {
            // Every other Python manager installs what it runs, and `uvx`
            // fetches the tool it names, so each reaches a registry.
            return false;
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
        // come first; `npm init <name>` runs a fetched initializer. A leading
        // option such as `--cwd dir` hides the verb and keeps the command out.
        let version_probe = arguments
            .iter()
            .all(|argument| matches!(*argument, "-v" | "--version" | "-h" | "--help"));
        let leading_verb = arguments
            .first()
            .is_some_and(|argument| !argument.starts_with('-'));
        let positional_init = arguments
            .iter()
            .position(|argument| *argument == "init")
            .is_some_and(|index| {
                arguments[index + 1..]
                    .iter()
                    .any(|argument| !argument.starts_with('-'))
            });
        !arguments.is_empty()
            && (leading_verb || version_probe)
            && !positional_init
            && !arguments
                .iter()
                .any(|argument| REGISTRY_VERBS.contains(&argument.to_ascii_lowercase().as_str()))
    })
}

#[cfg(test)]
#[path = "workspace_contained_cargo_tests.rs"]
mod cargo_tests;

#[cfg(test)]
#[path = "workspace_contained_uv_tests.rs"]
mod uv_tests;

#[cfg(test)]
#[path = "workspace_contained_go_tests.rs"]
mod go_tests;
