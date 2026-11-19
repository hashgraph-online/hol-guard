//! Whether the Windows read-only pytest profile can run a command at all.
//!
//! The AppContainer that profile launches can read an interpreter only under
//! the machine's Program Files folders, so the Windows planner refuses a
//! virtual environment whose `pyvenv.cfg` names a base Python installed for
//! one user (`%LOCALAPPDATA%\Programs\Python`, a uv-managed Python, a copy in
//! the home directory). Routing such a run to containment replaced its review
//! with a contained run that could only exit 126, so the run never happened
//! and no approval could start it. This reads the same `home` line the planner
//! reads and keeps the review when it names a base the container cannot run.
//!
//! Only a command that names its environment's launcher by path is read: the
//! activation projection rewrites `source .venv/bin/activate && pytest` to
//! `.venv/bin/pytest`. A bare `pytest` is resolved on the shell's `PATH`,
//! which the hook does not see, and keeps its containment.

// Only the Windows hook calls the reading; tests run it on every host.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::CanonicalCommandV1;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A `pyvenv.cfg` holds a handful of `key = value` lines.
const PYVENV_CFG_MAX_BYTES: u64 = 64 * 1024;
const BINARY_DIRECTORIES: [&str; 2] = ["Scripts", "bin"];

/// The `home` a virtual environment's `pyvenv.cfg` records.
fn recorded_home(environment: &Path) -> Option<PathBuf> {
    let file = std::fs::File::open(environment.join("pyvenv.cfg")).ok()?;
    // The limit holds for the read itself, so a file that grows after it is
    // opened is still refused.
    let mut text = String::new();
    file.take(PYVENV_CFG_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > PYVENV_CFG_MAX_BYTES {
        return None;
    }
    text.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("home"))
        .map(|(_, value)| PathBuf::from(value.trim()))
}

/// Whether `home` is an absolute path on a local drive, read without touching
/// the filesystem: a UNC share, a device namespace or a relative path is not.
fn local_absolute(home: &Path) -> bool {
    use std::path::{Component, Prefix};
    if !home.is_absolute() {
        return false;
    }
    match home.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        // Hosts without drive prefixes start an absolute path at the root.
        Some(Component::RootDir) => !cfg!(windows),
        _ => false,
    }
}

/// The environment a launcher path belongs to: `<environment>/<Scripts|bin>/<name>`.
fn environment_of(executable: &str, cwd: &Path) -> Option<PathBuf> {
    if !executable.contains(['/', '\\']) {
        return None;
    }
    let spelled = cwd.join(executable.replace('\\', "/"));
    // The planner follows a link to the launcher it names, so a link into an
    // environment is read at its target. The link is read, not resolved, so a
    // target on a share is never opened from here.
    let launcher = match std::fs::read_link(&spelled) {
        Ok(target) => {
            let target = spelled.parent()?.join(target);
            if !local_absolute(&target) {
                return None;
            }
            target
        }
        Err(_) => spelled,
    };
    let binaries = launcher.parent()?;
    let named = binaries.file_name()?.to_str()?;
    if !BINARY_DIRECTORIES
        .iter()
        .any(|directory| named.eq_ignore_ascii_case(directory))
    {
        return None;
    }
    binaries
        .parent()
        .filter(|environment| environment.join("pyvenv.cfg").is_file())
        .map(Path::to_path_buf)
}

/// Whether the pytest run names a virtual environment whose base Python sits
/// outside every one of `roots`, which the Windows planner refuses.
///
/// A command whose environment cannot be found here is left to the planner.
pub(super) fn base_outside_install_roots(
    model: &CanonicalCommandV1,
    cwd: Option<&str>,
    roots: &[PathBuf],
) -> bool {
    let (Some(cwd), [segment]) = (cwd, model.segments.as_slice()) else {
        return false;
    };
    let Some(environment) = segment
        .executable
        .as_deref()
        .and_then(|executable| environment_of(executable, Path::new(cwd)))
    else {
        return false;
    };
    // The planner refuses an environment whose base it cannot resolve. A
    // network or device `home` is refused before anything opens it, so a
    // repository's `pyvenv.cfg` cannot make the hook reach out to a share.
    let Some(base) = recorded_home(&environment)
        .filter(|home| local_absolute(home))
        .and_then(|home| home.join("python.exe").canonicalize().ok())
    else {
        return true;
    };
    !roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| base.starts_with(root))
}

/// [`base_outside_install_roots`] for the pytest run inside a wrapped
/// command, such as `cd api && .venv/bin/pytest -q` or a run piped into
/// `head`, read in the same core and directory the containment route uses.
pub(super) fn wrapped_base_outside_install_roots(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    roots: &[PathBuf],
) -> bool {
    super::restricted_test_commands::package_script::pytest_core(model, context).is_some_and(
        |(core, cwd)| {
            base_outside_install_roots(&core, cwd.as_deref().and_then(Path::to_str), roots)
        },
    )
}

/// [`wrapped_base_outside_install_roots`] against the machine's Program Files
/// folders.
#[cfg(windows)]
pub(super) fn base_outside_program_files(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    wrapped_base_outside_install_roots(
        model,
        context,
        &guard_runtime_windows_process::trusted_install_roots(),
    )
}

/// Only the Windows planner reads the base install; other hosts run the
/// environment's interpreter wherever it was installed.
#[cfg(not(windows))]
pub(super) fn base_outside_program_files(
    _model: &CanonicalCommandV1,
    _context: super::PathContext<'_>,
) -> bool {
    false
}

#[cfg(test)]
#[path = "windows_pytest_base_tests.rs"]
mod tests;
