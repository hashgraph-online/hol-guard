//! What a `uv` command reads, and whether the workspace already holds it.
//!
//! uv drives a project environment the workspace holds, so its local verbs
//! run workspace code the sandbox bounds. Which project holds that
//! environment is not the directory the command was typed in: `--directory`
//! moves the run and `--project` moves only the project a verb reads, either
//! may stand on one side of the verb or the other, and with neither, uv
//! ascends to the nearest `pyproject.toml`. Reading the command that far is
//! the whole of this module; [`super::local_package_work`] asks it for the
//! answer.
//!
//! The sandbox has no network, so everything that would have to fetch keeps
//! the admission it has today rather than failing inside it: uv's installing
//! verbs, an option that adds a dependency or re-resolves one, a script
//! carrying its own dependency block, and a project whose `.venv` uv has yet
//! to materialize.

use std::path::{Path, PathBuf};

// uv drives a project environment the workspace holds. Only the verbs that
// read it are local: `add`, `tool`, `sync` and the rest reach a registry, and
// `pip` is local for the queries [`super::super::python`] admits.
const UV_LOCAL_VERBS: &[&str] = &["run", "tree", "export", "version", "pip"];
// `uv lock` writes the lockfile, so it is not a local verb; the one spelling
// that only reports on it is read below.
const UV_LOCK_ASSERTIONS: &[&str] = &["--check", "--locked"];
// uv options a local verb may carry: each changes what the verb reads, never
// what it has to fetch. The list is an allowlist because uv's installing
// options are many and grow: an option this module does not know keeps the
// command out, where it keeps the admission it has today.
const UV_VERB_FLAGS: &[&str] = &[
    "--frozen",
    "--locked",
    "--check",
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

/// What a `uv` command was told to do: where its verb stands, the directory
/// the verb runs in, the project whose environment it reads, and the operand
/// that follows the verb's own options.
struct UvCommand {
    verb: usize,
    directory: PathBuf,
    project: PathBuf,
    discovered: bool,
    operand: Option<usize>,
    /// Whether a lock assertion flag stood on its own rather than being read
    /// as another option's value.
    asserts: bool,
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
    let mut asserts = false;
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
                asserts = asserts || UV_LOCK_ASSERTIONS.contains(&name);
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
        Some(target) => super::entered(directory, target, workspace)?,
        None => directory.to_owned(),
    };
    let project = match named {
        Some(target) => super::entered(&run, target, workspace)?,
        None => run.clone(),
    };
    Some(UvCommand {
        verb,
        directory: run,
        project,
        discovered: named.is_none(),
        operand,
        asserts,
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
pub(super) fn local_uv_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let Some(uv) = uv_command(arguments, directory, workspace) else {
        return false;
    };
    let verb = arguments[uv.verb].to_ascii_lowercase();
    // `uv lock` resolves the project's dependencies and rewrites `uv.lock`.
    // `--check`, which uv spelled `--locked` first, asks the opposite: it
    // asserts the lockfile already satisfies `pyproject.toml` and exits
    // non-zero when it does not, writing nothing either way. That is the read
    // of the project `uv tree` already makes. `--dry-run` is absent because
    // it resolves the dependencies afresh to report what would change, which
    // is the fetch the sandbox has no network for.
    // The flag has to stand on its own: `uv lock --env-file --check` reads
    // `--check` as the file's name, so uv still resolves and rewrites the
    // lockfile.
    let asserts_the_lock = verb == "lock" && uv.asserts;
    if !UV_LOCAL_VERBS.contains(&verb.as_str()) && !asserts_the_lock {
        return false;
    }
    if verb == "pip" {
        return super::super::python::local_uv_pip_work(&arguments[uv.verb + 1..], &uv.project);
    }
    if let Some(operand) = uv.operand.map(|operand| arguments[operand]) {
        // `uv version 2.0.0` writes the version into the project and locks it
        // again, a script named by URL is downloaded before it runs, and a
        // script carrying a dependency block has those installed first.
        if verb == "version"
            || operand.contains("://")
            || super::super::python::declares_dependencies(&uv.directory.join(operand))
        {
            return false;
        }
    }
    if !uv.discovered {
        return uv.project.join(".venv").is_dir();
    }
    super::super::cd::first_from(&uv.project, workspace, |probe| {
        probe.join("pyproject.toml").is_file()
    })
    .is_some_and(|project| project.join(".venv").is_dir())
}
