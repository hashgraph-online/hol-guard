//! Python package managers running a read-only query, and the project
//! runners that launch a program the environment already holds.
//!
//! [`super::package`] keeps every Python manager out of the contained route
//! because each one installs what it runs, and an install the sandbox has no
//! network for would fail where it works today. A query is the other half of
//! that surface: `pip list`, `pip freeze` and `pip show` report what an
//! environment already holds, write nothing and reach no registry, so the
//! sandbox bounds them the way it bounds `npm ls` or `cargo tree`. Without
//! this the same listing is the one shape of ordinary work that stops for an
//! approval in an ecosystem whose neighbours stay quiet.
//!
//! `poetry run` and `pipenv run` are the other shape. They launch a program
//! out of the project's own environment, which is what `uv run` does, and the
//! contained route already carries that: `uv run`, and every runner this
//! module names no verb for at all, routes into the sandbox today, nested
//! `pip install` and all. The sandbox is where a nested program is bounded —
//! no network, no home, writes inside the workspace — so holding these two
//! back bought no protection and cost a poetry project its most ordinary
//! command. They are admitted on the proof `uv` is admitted on: a `.venv`
//! the project already materialized. Without one the runner would have to
//! build the environment first, and a Poetry virtualenv kept under its own
//! cache home is one the sandbox replaces, so both keep their review.
//!
//! The reading surface is pip's own, so [`super::super::pip_reads`] decides it
//! here as well: one allowlist of subcommands, options and operands serves the
//! path-spelled `pip` a project runs and the `uv pip` that drives the same
//! environment.
//!
//! A contained run is given the workspace as its `HOME`, so only the reads
//! that resolve from the environment's own prefix are routed here. What pip
//! finds through the home directory — its cache, the user site — and every
//! `pipx` query, which reports the layout under pipx's own home, would answer
//! for the sandbox rather than the developer. Those keep the review they have
//! today until the runner can show the contained command the real directory.

use std::path::Path;

/// Whether a Python manager segment runs a query, or a runner verb, against
/// an environment that already exists. `uvx` fetches the tool it names and
/// `pipx` reports a home the sandbox replaces, so neither reaches this.
///
/// The pip has to be a virtual environment's own. Outside one, pip reports the
/// user site under the home directory as well, which the sandbox replaces, so
/// a bare `pip list` would describe the sandbox and `pip show` would miss the
/// packages the developer installed for themselves. That is the same wrong
/// environment the `--user` and cache spellings are kept out for.
pub(super) fn local_python_work(
    name: &str,
    executable: &str,
    arguments: &[String],
    directory: &Path,
) -> bool {
    match name {
        "pip" | "pip3" => {
            let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
            virtual_environment_executable(executable, directory)
                && super::super::pip_reads::environment_read_words(&words)
        }
        "poetry" => local_poetry_work(arguments, directory),
        "pipenv" => local_pipenv_work(arguments, directory),
        _ => false,
    }
}

/// Flags that report differently without changing what Poetry runs, so the
/// verb standing behind one is still the verb.
const POETRY_INERT_FLAGS: &[&str] = &["--no-ansi", "--no-interaction", "-n", "--quiet", "-q"];

/// Poetry verbs the sandbox bounds: the two reads that are provable without
/// launching anything, and `run`, which launches out of the project's
/// environment the way `uv run` does.
///
/// Poetry accepts its global project-moving options before the subcommand as
/// well as after it. One standing in front is rejected here by arriving as
/// the verb, which matches no arm; one standing behind a read is rejected by
/// that read's own word list, which also keeps out `--`: `poetry version --
/// patch` writes the manifest rather than reporting it.
fn local_poetry_work(arguments: &[String], directory: &Path) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let mut rest = words
        .iter()
        .copied()
        .skip_while(|word| POETRY_INERT_FLAGS.contains(word));
    let Some(verb) = rest.next() else {
        return false;
    };
    let tail: Vec<&str> = rest.collect();

    match verb {
        "run" => launches_a_materialized_environment(&tail, directory),
        "check" => bounded_read(&tail, "--lock", POETRY_INERT_FLAGS),
        "version" => bounded_read(&tail, "--short", POETRY_INERT_FLAGS),
        _ => false,
    }
}

/// Flags that report differently without changing what Pipenv runs.
const PIPENV_INERT_FLAGS: &[&str] = &["--quiet", "-q"];

/// Pipenv's `run` reads the same way Poetry's does: the words after the verb
/// are the nested program's, and the project's `.venv` is what proves the
/// environment is already there. Pipenv's own options — `--python`, `--venv`,
/// the ones that build or relocate an environment — stand in front of the
/// verb, so they arrive here as the verb and match no arm.
fn local_pipenv_work(arguments: &[String], directory: &Path) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let mut rest = words
        .iter()
        .copied()
        .skip_while(|word| PIPENV_INERT_FLAGS.contains(word));
    let Some(verb) = rest.next() else {
        return false;
    };
    let tail: Vec<&str> = rest.collect();

    match verb {
        "run" => launches_a_materialized_environment(&tail, directory),
        _ => false,
    }
}

/// Whether a runner's `run` names a program to launch out of an environment
/// the project already materialized.
///
/// The words after `run` belong to the nested program, not to the runner, so
/// nothing in them is read as an option here — `poetry run pytest -C tests`
/// is pytest's flag. What the runner itself can still take is a leading `--`,
/// which only ends its own parsing, and a first word that is an option rather
/// than a program name is the runner's again, so that shape is left alone.
///
/// `.venv` beside the project is the same proof [`super::package`] admits
/// `uv run` on. Without it the runner materializes an environment before it
/// runs anything, which needs the network the sandbox withholds, and a
/// virtualenv kept under the runner's own cache home is one the contained
/// `HOME` replaces — both keep the review they have today. The directory has
/// to hold an environment, not just carry the name: an empty `.venv`, or one
/// built against the developer's own site packages, sends the runner looking
/// for an environment elsewhere, and that is the wrong one to launch out of.
fn launches_a_materialized_environment(tail: &[&str], directory: &Path) -> bool {
    let tail = match tail.split_first() {
        Some((first, rest)) if *first == "--" => rest,
        _ => tail,
    };
    let Some(program) = tail.first() else {
        return false;
    };
    !program.starts_with('-') && isolated_virtual_environment(&directory.join(".venv"))
}

/// Whether a read's words are only the one option it reports differently for
/// and the flags that change nothing. Anything else — an operand, a project
/// mover, a `--` that hides one — is not that read.
fn bounded_read(tail: &[&str], option: &str, inert: &[&str]) -> bool {
    tail.iter()
        .all(|word| *word == option || inert.contains(word))
}

/// Whether the spelled executable lives in a virtual environment's `bin`. The
/// prefix beside that directory holds `pyvenv.cfg`, which is what makes the
/// environment one pip reads without the user site. A bare name carries no
/// prefix to check, so it is never one.
fn virtual_environment_executable(executable: &str, directory: &Path) -> bool {
    let spelled = Path::new(executable);
    if spelled
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
    {
        return false;
    }
    let resolved = if spelled.is_absolute() {
        spelled.to_owned()
    } else {
        directory.join(spelled)
    };
    resolved
        .parent()
        .and_then(Path::parent)
        .is_some_and(isolated_virtual_environment)
}

/// Whether the prefix holds a virtual environment pip reads without the user
/// site.
///
/// `pyvenv.cfg` is what makes a prefix one, and the file's
/// `include-system-site-packages` key is what decides whether the user site
/// stays enabled inside it: `python -m venv --system-site-packages` writes it
/// true, and CPython then leaves `ENABLE_USER_SITE` on, so `pip list` in that
/// environment still reports what the developer installed under their own
/// home. The sandbox replaces that home, so such an environment answers for
/// the sandbox and keeps the review it has today — the same wrong environment
/// the bare `pip` and the `--user` spellings are kept out for.
///
/// A missing, unreadable or directory-shaped `pyvenv.cfg` reads as no
/// environment, which is the answer a prefix that is not one should give.
fn isolated_virtual_environment(prefix: &Path) -> bool {
    let Ok(config) = std::fs::read_to_string(prefix.join("pyvenv.cfg")) else {
        return false;
    };
    !config.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim()
                .eq_ignore_ascii_case("include-system-site-packages")
                && value.trim().eq_ignore_ascii_case("true")
        })
    })
}

/// Whether `uv pip <rest>` is one of pip's own queries against the project's
/// environment. uv puts pip's surface in front of that environment, so the
/// words after `pip` are read by the same allowlist, and an install or a sync
/// falls out of it there too. Without a materialized `.venv` beside the
/// project uv searches for an environment of its own, which the listing would
/// then describe, so the environment has to be one the same way the spelled
/// pip's is: a directory holding `pyvenv.cfg` is not enough on its own, and an
/// empty `.venv` is not an environment at all.
pub(super) fn local_uv_pip_work(words: &[&str], project: &Path) -> bool {
    super::super::pip_reads::environment_read_words(words)
        && isolated_virtual_environment(&project.join(".venv"))
}

#[cfg(test)]
#[path = "workspace_contained_python_tests.rs"]
mod python_tests;
