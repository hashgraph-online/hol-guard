//! A marked virtual environment's own interpreter, spelled by path.
//!
//! The exact-safe floor refuses a path-spelled executable. A name looked up
//! on `PATH` reaches a program the trusted-location screen has vetted, while
//! a path reaches whatever file it names, so the basename the command would
//! otherwise be judged by proves nothing about what runs.
//!
//! `.venv/bin/python --version` is the shape that pays for that rule without
//! being what it guards against. It is the same program the activation
//! projection already hands on: `source .venv/bin/activate && python -V`
//! is rewritten to exactly this spelling before the floor reads it, so a
//! marked environment's own `bin` is a place Guard already resolves programs
//! out of. A command that names that file directly, the way an agent does
//! when it would rather not activate, runs the same program.
//!
//! Three things have to hold together, because any one of them alone is a
//! hole. PEP 405 puts `pyvenv.cfg` directly above `bin`, and only `venv`,
//! `virtualenv` and `uv` write it, so the marker says the directory is an
//! environment — but the agent writes the workspace, so it can write a marker
//! and a `bin` beside it. The basename has to be an interpreter's, because
//! the floor judges the command by that name: a file called `ls` or `git` in
//! a marked `bin` would otherwise inherit the verdict of the program on
//! `PATH` it is not. And the file has to resolve out of the environment, to a
//! regular file outside the working directory, because that is what an
//! environment's interpreter is: a link to the base interpreter it was built
//! from. A script the session wrote at `bin/python` resolves to itself,
//! inside the environment, and is refused.
//!
//! Windows environments copy the interpreter instead of linking it, so the
//! copy resolves to itself inside the environment and keeps its review there.
//! Nothing about a copy inside the workspace distinguishes it from a planted
//! one by path alone, and reading both files to compare them is not a cost
//! this screen pays; the activation route stays available on that platform.
//!
//! This proves only which file the word names. The basename still decides
//! what the command may do with it.
//!
//! The bounded-read screen is deliberately not the gate here. It answers a
//! different question, and both of its answers are wrong for this one: it
//! would admit the link's target as a readable path without asking where it
//! leads, while the hidden-path rule refuses `.venv/bin/python` itself. The
//! word's own spelling and the location screens are what this rule owes.

use std::path::Path;

/// A name a virtual environment tool writes for the interpreter itself:
/// `python`, `python3`, `python3.12`, and the free-threaded `python3.13t`.
fn interpreter_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    let stem = lowered.strip_suffix(".exe").unwrap_or(lowered.as_str());
    if stem == "python" || stem == "python3" {
        return true;
    }
    stem.strip_prefix("python3.").is_some_and(|version| {
        let digits = version.strip_suffix('t').unwrap_or(version);
        !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
    })
}

pub(super) fn environment_program(executable: &str, context: super::PathContext<'_>) -> bool {
    // `~` is the shell's own name for the real home, and a relative root
    // would resolve the spelling against Guard's working directory instead of
    // the command's. Neither root is a guess this screen makes.
    if !super::read_paths::verified_path_context(context.home_dir, context.cwd)
        || !super::read_paths::bounded_path_spelling(executable)
    {
        return false;
    }
    let Ok(candidate) = guard_secure_fs::resolve_candidate(
        executable,
        context.cwd.map(Path::new),
        Path::new(context.home_dir.unwrap_or_default()),
    ) else {
        return false;
    };
    let (Some(parent), Some(program)) = (candidate.parent(), candidate.file_name()) else {
        return false;
    };
    if !interpreter_name(&program.to_string_lossy()) {
        return false;
    }
    let Ok(binaries) = std::fs::canonicalize(parent) else {
        return false;
    };
    // POSIX environments keep their programs in `bin`, Windows ones in
    // `Scripts`; the marker sits directly above either. The directory is
    // canonical before the marker is read, so no link can dress another place
    // as an environment.
    if !binaries
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|name| name == "bin" || name == "scripts")
    {
        return false;
    }
    let Some(root) = binaries.parent() else {
        return false;
    };
    if !root.join("pyvenv.cfg").is_file() {
        return false;
    }
    let named = binaries.join(program);
    // The directory above is canonical, so the system roots, another user's
    // home, the sensitive families and the credential-named paths are read
    // off a place no link can have dressed up.
    if !super::read_paths::resolved_location_allowed(&named, context.home_dir, context.cwd, false) {
        return false;
    }
    let Ok(resolved) = std::fs::canonicalize(&named) else {
        return false;
    };
    if !resolved.is_file() || resolved.starts_with(root) {
        return false;
    }
    // The name the link lands on has to be an interpreter too. A link spelled
    // `python` that reaches another program would hand that program the
    // interpreter's verdict, which is the whole of what this screen grants.
    if !resolved
        .file_name()
        .is_some_and(|name| interpreter_name(&name.to_string_lossy()))
    {
        return false;
    }
    // The file that runs is screened at its own canonical place, not at the
    // name that reached it: the system roots, another user's home, the
    // sensitive families and the credential-named paths all read the target.
    if !super::read_paths::resolved_location_allowed(
        &resolved,
        context.home_dir,
        context.cwd,
        false,
    ) {
        return false;
    }
    // The workspace is where the session writes without review, so an
    // interpreter the link reaches inside it is the planted file one step out.
    // The checkout around the working directory is that workspace, not just
    // the directory a command happens to run from, or a link from a
    // subdirectory would reach the rest of the tree unread. A working
    // directory this screen cannot resolve leaves the question unanswered,
    // which is the same answer.
    let Some(cwd) = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    let workspace = nearest_checkout(&cwd).unwrap_or(cwd);
    !resolved.starts_with(workspace)
}

/// The checkout the working directory sits in, which the session writes
/// without a review of its own.
fn nearest_checkout(cwd: &Path) -> Option<std::path::PathBuf> {
    cwd.ancestors()
        .find(|directory| directory.join(".git").symlink_metadata().is_ok())
        .map(Path::to_path_buf)
}

#[cfg(test)]
#[path = "venv_program_path_tests.rs"]
mod tests;
